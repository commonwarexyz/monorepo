//! The proof builder (optimizer design §11.3): the equality lemma of a
//! driven residual, built by walking the residual's committed body and the
//! source's body **side by side, as terms**, replaying the process tree —
//! `opt::mirror` generalized from two α-equal bodies to a residual and the
//! source unfolded along the process graph.
//!
//! The goal is `Eq(R, L, S)` ([`super::steps::Goal`]) with `L` a subterm of
//! the residual and `S` a subterm of the source (unfolded by `Delta` where
//! the driver unfolded). At each node of the tree the builder
//!
//! 1. walks the `let`s of both sides (each becomes a `let` of the proof:
//!    `let x = v; P` proves the goal with `x := v`, by ζ), and
//!    head-normalizes the source: β, ι on a scrutinee that evaluates to a
//!    constructor, δ of a non-opaque non-recursive definition — all
//!    definitional, so no proof term;
//! 2. applies the node's steps to the source's head: `Delta` of a folded
//!    application, or a decision of its head match (`Prune` by linarith,
//!    `Reuse` by a path equation), each a `transport` whose motive is the
//!    source's head with the rewritten position replaced by the motive
//!    variable (and the dependent-match idiom's path-equation argument by
//!    the motive's equation binder);
//! 3. closes the goal by conversion (`refl(R, L)`) when both sides agree —
//!    which also covers matches the residual keeps in place;
//! 4. otherwise splits: both sides have a match at the head on convertible
//!    scrutinees; the dependent-match idiom's motive replaces the two
//!    scrutinees (and their idiom arguments), each arm binds the
//!    constructor's fields and the path equation — exactly the binders the
//!    driver introduced — and continues with both sides' arms. At a leaf of
//!    the tree the goal goes to `auto`.
//!
//! Motives are syntactic (no value is ever read back into a motive), so a
//! goal stays as large as the two terms, and every motive is well typed by
//! construction (the arms keep their own path equations). Values are used
//! only to decide: conversion at the leaves and linarith for `Prune`.
//! Residual and source `let`s are definitional in the typing context and
//! opaque in the evaluation view that linarith reads, which keeps its
//! atoms small.
//!
//! The kernel checks the lemma when it is added (`Env::add_def`); nothing
//! here is trusted.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use sandblaster_kernel::api::CtxEntry;
use sandblaster_kernel::term::{Arm, DefKind, GlobalId, Idx, IndId, Lvl, Rel, Term, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Closure, EnvEntry, V, VEnv, Value};

use super::steps::{Goal, Wrap, head_reduce, subst_n};
use crate::auto::search::Engine;
use crate::auto::state::St;
use crate::auto::util::{shift, shift_from, venv_push};
use crate::opt::drive::tree::{Node, NodeKind, Step};

/// Statistics of one proof.
#[derive(Clone, Debug, Default)]
pub struct ProofStats {
    pub steps_applied: u32,
    pub steps_absent: u32,
    pub splits: u32,
    pub leaves_refl: u32,
    pub leaves_auto: u32,
    pub lets: u32,
}

/// The walk's state.
pub struct Walk {
    pub stats: ProofStats,
    /// Driver level → proof level (split fields and path equations).
    pub lvl: HashMap<u32, u32>,
    /// The specialization helpers the residual calls, with their lemmas.
    pub specs: super::Specs,
    /// The value terms of the `let`s in scope, by level (each at the depth
    /// of its level).
    pub let_terms: HashMap<u32, Tm>,
    /// Globals the driver kept folded (its opaque set among the transparent
    /// definitions): head normalization does not unfold them either (a
    /// kept call is unfolded only by an `Unfold` step).
    pub folded: std::collections::HashSet<GlobalId>,
    /// A simulated fault is active (the must-reject suite): the builder
    /// trusts the driver's claims — decisions it cannot re-derive become
    /// certificate-free `linarith` terms and leaves are closed by `refl` —
    /// so the kernel, not the builder, has to reject them.
    pub trust: bool,
    /// Steps of the `auto` search at one leaf ([`super::Budgets`]).
    pub leaf_steps: u64,
    /// The type terms of the irrelevant binders the walk introduced
    /// (`let`s of either side, path equations), by level, each at the depth
    /// of its level (see `steps::fact_types`).
    pub fact_terms: HashMap<u32, Tm>,
    /// The term of the condition a decision is replayed on (its leaves'
    /// subterms go into the decision's proof, shared with the goal).
    pub cond_tm: Option<Tm>,
    /// The outlined `(type, body)` of the definitions the proof unfolds
    /// (`opt::outline`).
    pub outlined: HashMap<GlobalId, Rc<(Tm, Tm)>>,
    /// Fold helpers the residual calls, by the recursion they fold:
    /// `(helper, lemma)` (`Step::FoldCall`).
    pub folds: HashMap<GlobalId, (GlobalId, GlobalId)>,
    /// Building a fold helper's own lemma: its back-edges (`Step::Fold`)
    /// are the lemma's induction hypothesis.
    pub own_fold: Option<OwnFold>,
    /// The function whose lemma is being built (Σ3 back-edges call it).
    pub res: GlobalId,
    /// `slice::mk` (a projection of a `let`-bound slice built by it reduces).
    pub slice_mk: Option<GlobalId>,
}

/// The fold helper whose lemma is being built (see [`Walk::own_fold`]).
#[derive(Clone, Debug)]
pub struct OwnFold {
    /// The recursion folded.
    pub def: GlobalId,
    /// The lemma's measure (a term over its telescope) and the telescope's
    /// length.
    pub measure: Tm,
    pub arity: u32,
}

type W<T> = Result<T, String>;

thread_local! {
    /// Memo of shifted terms, by (term address, amount, cutoff): a subterm
    /// shifted by the same amount again — the residual's remainder under
    /// every motive of a node — is the same copy, so the proof shares it
    /// (cleared per proof, [`clear_shift_memo`]; the original is kept so
    /// its address is not reused).
    static SHIFT_MEMO: std::cell::RefCell<ShiftMemo> = std::cell::RefCell::new(HashMap::new());
}

/// Shifted copies by (term address, amount, cutoff), with the original.
type ShiftMemo = HashMap<(usize, i64, u32), (Tm, Tm)>;

/// Forgets the shifted copies of the previous proof.
pub fn clear_shift_memo() {
    SHIFT_MEMO.with(|m| m.borrow_mut().clear());
}

/// `shift_from(t, k, cutoff)`, memoized (see [`SHIFT_MEMO`]).
fn csh_from(t: &Tm, k: i64, cutoff: u32) -> Tm {
    if k == 0 {
        return t.clone();
    }
    let key = (Rc::as_ptr(t) as usize, k, cutoff);
    if let Some(r) = SHIFT_MEMO.with(|m| m.borrow().get(&key).map(|(_, r)| r.clone())) {
        return r;
    }
    let r = shift_from(t, k, cutoff);
    SHIFT_MEMO.with(|m| m.borrow_mut().insert(key, (t.clone(), r.clone())));
    r
}

/// `shift(t, k)`, memoized.
fn csh(t: &Tm, k: i64) -> Tm {
    csh_from(t, k, 0)
}

/// Kernel steps of one replayed decision (see [`Walk::replay_decision`]).
const DECISION_STEPS: u64 = 8_000_000;

/// A residual side larger than this (term nodes) under source-side steps
/// is bound by a `let` ([`Walk::node`]).
const LET_L_NODES: usize = 64;

/// A match at the head of a term: `(match scrut as y return motive with
/// arms) [idiom]`.
struct HeadMatch {
    ind: IndId,
    params: Vec<Tm>,
    scrut: Tm,
    motive: Tm,
    arms: Vec<Arm>,
    /// The dependent-match idiom's path-equation argument.
    idiom: Option<Tm>,
}

impl HeadMatch {
    fn of(t: &Tm) -> Option<HeadMatch> {
        let (m, idiom) = match &**t {
            Term::App { rel: Rel::Irr, fun, arg } if matches!(&**fun, Term::Match { .. }) => (fun, Some(arg.clone())),
            Term::Match { .. } => (t, None),
            _ => return None,
        };
        let Term::Match { ind, params, scrut, motive, arms } = &**m else { return None };
        Some(HeadMatch { ind: *ind, params: params.clone(), scrut: scrut.clone(), motive: motive.clone(), arms: arms.iter().map(|a| Arm { names: a.names.clone(), body: a.body.clone() }).collect(), idiom })
    }

    /// The match on `new`, a scrutinee definitionally equal to its own: a
    /// dependent-match idiom still on its original `refl` is re-based on
    /// `new` (its motive's equation from `new`, the argument `refl(D,
    /// new)`), so a later abstraction of a subterm of `new` sees and
    /// transports the path equation; otherwise the idiom argument stays.
    fn renormalized(&self, new: Tm) -> Tm {
        if let Some(a) = &self.idiom
            && let Term::Refl { ty, .. } = &**a
            && let Term::Pi { name, rel, dom, cod } = &*self.motive
            && let Term::Eq { ty: dty, rhs, .. } = &**dom
            && matches!(&**rhs, Term::Var(Idx(0)))
        {
            let motive: Tm = Rc::new(Term::Pi { name: name.clone(), rel: *rel, dom: mk::eq(dty.clone(), shift(&new, 1), rhs.clone()), cod: cod.clone() });
            let m = HeadMatch { ind: self.ind, params: self.params.clone(), scrut: self.scrut.clone(), motive, arms: self.arms.iter().map(|a| Arm { names: a.names.clone(), body: a.body.clone() }).collect(), idiom: None };
            return mk::app_irr(m.rebuild(0, new.clone(), None), mk::refl(ty.clone(), new));
        }
        self.rebuild(0, new, None)
    }

    /// The match's own subterms shifted by `k` (it moves under `k` new
    /// binders).
    fn shifted(&self, k: u32) -> HeadMatch {
        HeadMatch {
            ind: self.ind,
            params: self.params.iter().map(|p| csh(p, k as i64)).collect(),
            scrut: csh(&self.scrut, k as i64),
            motive: csh_from(&self.motive, k as i64, 1),
            arms: self.arms.iter().map(|a| Arm { names: a.names.clone(), body: csh_from(&a.body, k as i64, a.names.len() as u32) }).collect(),
            idiom: self.idiom.as_ref().map(|a| csh(a, k as i64)),
        }
    }

    /// The match with its scrutinee replaced by `y` and its idiom argument
    /// by `e` (terms at the target depth; the match's own subterms shifted
    /// by `k`, the binders between).
    fn rebuild(&self, k: u32, y: Tm, e: Option<Tm>) -> Tm {
        let arms = self.arms.iter().map(|a| Arm { names: a.names.clone(), body: csh_from(&a.body, k as i64, a.names.len() as u32) }).collect();
        let m: Tm = Rc::new(Term::Match { ind: self.ind, params: self.params.iter().map(|p| csh(p, k as i64)).collect(), scrut: y, motive: csh_from(&self.motive, k as i64, 1), arms });
        match (&self.idiom, e) {
            (Some(_), Some(e)) => mk::app_irr(m, e),
            (Some(a), None) => mk::app_irr(m, csh(a, k as i64)),
            (None, _) => m,
        }
    }
}

/// `match (let x = v; b) ..` as `let x = v; match b ..` (also through
/// nested scrutinees): definitionally equal (ζ). `None` when no scrutinee
/// on the chain is a `let`.
fn float_let(t: &Tm) -> Option<Tm> {
    let hm = HeadMatch::of(t)?;
    let inner = match &*hm.scrut {
        // `let x = v; x` is `v` (a join's value: nothing is copied)
        Term::Let { rel: Rel::Rel, val, body, .. } if matches!(&**body, Term::Var(Idx(0))) => return Some(hm.renormalized(val.clone())),
        Term::Let { .. } => hm.scrut.clone(),
        _ => float_let(&hm.scrut)?,
    };
    let Term::Let { name, rel, ty, val, body } = &*inner else { return None };
    Some(Rc::new(Term::Let { name: name.clone(), rel: *rel, ty: ty.clone(), val: val.clone(), body: hm.shifted(1).renormalized(body.clone()) }))
}

/// `t` with its innermost nested match on a constructor ι-reduced: `t` is
/// a match whose scrutinee is (transitively) a match on `Cₖ(ā)`; `None`
/// when there is none.
fn iota_inner(t: &Tm) -> Option<Tm> {
    let hm = HeadMatch::of(t)?;
    if matches!(&*hm.scrut, Term::Ctor { .. }) {
        let r = head_reduce(t);
        return (!Rc::ptr_eq(&r, t)).then_some(r);
    }
    let inner = iota_inner(&hm.scrut)?;
    Some(hm.renormalized(inner))
}

/// The folded application at the head of a term: `(g, args)`.
fn head_app(t: &Tm) -> Option<(GlobalId, Vec<(Rel, Tm)>)> {
    let mut args = Vec::new();
    let mut h = t;
    while let Term::App { rel, fun, arg } = &**h {
        args.push((*rel, arg.clone()));
        h = fun;
    }
    let Term::Global(g) = &**h else { return None };
    args.reverse();
    Some((*g, args))
}

/// `def`'s body applied to `args` as `let`s: `let x₁ : A₁ = a₁; …; body`
/// (definitionally `body[ā]`, by ζ), so arguments are not copied into every
/// occurrence of their parameter.
fn body_with_lets(env: &sandblaster_kernel::api::Env, def: GlobalId, args: &[Tm], outlined: Option<&(Tm, Tm)>) -> Option<Tm> {
    // the outlined type and body when there are (`opt::outline`: the same
    // up to irrelevant positions, cheaper to re-check in every copy)
    let (mut ty, mut body) = match outlined {
        Some((t, b)) => (t.clone(), b.clone()),
        None => (env.global_type(def)?, env.global_body(def)?),
    };
    let mut binders = Vec::new();
    for _ in 0..args.len() {
        let (Term::Pi { name, rel, dom, cod }, Term::Lam { body: b, .. }) = (&*ty.clone(), &*body.clone()) else { return None };
        binders.push((name.clone(), *rel, dom.clone()));
        ty = cod.clone();
        body = b.clone();
    }
    for (i, (name, rel, dom)) in binders.into_iter().enumerate().rev() {
        body = Rc::new(Term::Let { name, rel, ty: dom, val: shift(&args[i], i as i64), body });
    }
    Some(body)
}

/// Transitivity by transport: `trans(p : Eq(A, a, b), q : Eq(A, b, c)) =
/// transport(A, b, c, q, z. Eq(A, a, z), p) : Eq(A, a, c)`.
fn trans_tm(a_tm: &Tm, a: &Tm, b: &Tm, c: &Tm, p: &Tm, q: &Tm) -> Tm {
    Rc::new(Term::Transport { ty: a_tm.clone(), lhs: b.clone(), rhs: c.clone(), eq: q.clone(), motive: mk::eq(shift(a_tm, 1), shift(a, 1), mk::var(0)), val: p.clone() })
}

/// The scrutinee a dependent-match idiom's motive names:
/// `y. Π(e :Irr Eq(A, s₀, y)). R` gives `s₀`.
fn idiom_scrut(hm: &HeadMatch) -> Option<Tm> {
    let Term::Pi { dom, .. } = &*hm.motive else { return None };
    let Term::Eq { lhs, .. } = &**dom else { return None };
    if sandblaster_kernel::util::occurs(lhs, 0) {
        return None;
    }
    Some(shift(lhs, -1))
}

/// Symmetry by transport:
/// `transport(A, a, b, p, z. Eq(A, z, a), refl(A, a)) : Eq(A, b, a)`.
fn sym_tm(a_tm: &Tm, a: &Tm, b: &Tm, p: &Tm) -> Tm {
    Rc::new(Term::Transport { ty: a_tm.clone(), lhs: a.clone(), rhs: b.clone(), eq: p.clone(), motive: mk::eq(shift(a_tm, 1), mk::var(0), shift(a, 1)), val: mk::refl(a_tm.clone(), a.clone()) })
}

/// A proof closure read back (through a pair).
fn irr_tm(e: &Engine<'_>, st: &St, c: &Closure) -> Tm {
    let p = Rc::new(Value::Pair { fst: Rc::new(Value::Lit { w: sandblaster_kernel::term::Width::Int, n: 0.into() }), snd: Arg::Irr(c.clone()) });
    match &*e.env.quote(Lvl(st.depth()), &p, false) {
        Term::Pair { snd, .. } => snd.clone(),
        _ => Rc::new(Term::Erased),
    }
}

impl Walk {
    fn eval_full(&self, e: &mut Engine<'_>, st: &St, t: &Tm) -> W<V> {
        e.settle();
        let venv = e.env.ctx_venv(&st.ctx);
        e.env.eval(&venv, Lvl(st.depth()), t, e.b).map_err(|err| format!("evaluation: {err:?}"))
    }

    fn eval(&self, e: &mut Engine<'_>, st: &St, t: &Tm) -> W<V> {
        e.settle();
        st.eval(e.env, t, e.b).map_err(|err| format!("evaluation: {err:?}"))
    }

    /// `t` (a term at depth `d`) with the `let` variables that stand for
    /// bit-level values replaced by those values, recursively: a variable
    /// whose value is (after the same expansion, and ι of a projection of a
    /// constructor: a tuple field bound by `let (v, rest) = ..`) an
    /// operation (`|`, `&`, `^`, shifts, casts, wrapping and checked
    /// arithmetic, comparisons), a literal or another variable. At most
    /// `fuel` replacements.
    fn expand_bit_lets(&self, t: &Tm, d: u32, fuel: u32) -> Tm {
        use sandblaster_kernel::term::PrimOp::*;
        let mut fuel = fuel;
        fn is_bit(t: &Tm) -> bool {
            matches!(&**t, Term::Var(_) | Term::Lit { .. } | Term::Prim { op: Or(_) | And(_) | Xor(_) | Not(_) | WShl(_) | WShr(_) | Shl(_) | Shr(_) | Cast { .. } | WAdd(_) | WSub(_) | WMul(_) | Add(_) | Sub(_) | Mul(_) | Lt(_) | Le(_) | Gt(_) | Ge(_) | Eq(_) | Ne(_), .. })
        }
        // `t` at depth `d + k` (k binders below the context)
        fn walk(this: &Walk, t: &Tm, k: u32, d: u32, fuel: &mut u32) -> Tm {
            match &**t {
                Term::Var(Idx(i)) if *i >= k => {
                    let lvl = (d + k).checked_sub(1 + i);
                    if let Some(lvl) = lvl
                        && lvl < d
                        && *fuel > 0
                        && let Some(def) = this.let_terms.get(&lvl)
                    {
                        *fuel -= 1;
                        let v = walk(this, &shift(def, (d + k - lvl) as i64), k, d, fuel);
                        if std::env::var_os("SANDBLASTER_OPT_TRACE_EXPAND").is_some() {
                            eprintln!("opt: proof: expand let at {lvl}: def {:?} -> {:?} bit {}", std::mem::discriminant(&**def), std::mem::discriminant(&*v), is_bit(&v));
                        }
                        if is_bit(&v) {
                            return v;
                        }
                    }
                    t.clone()
                }
                Term::Prim { op, args, proofs } => {
                    let args2: Vec<Tm> = args.iter().map(|a| walk(this, a, k, d, fuel)).collect();
                    Rc::new(Term::Prim { op: *op, args: args2, proofs: proofs.clone() })
                }
                // a projection of a constructor (ι)
                Term::Match { scrut, arms, .. } if arms.len() == 1 => {
                    let sc = walk(this, scrut, k, d, fuel);
                    if let Term::Ctor { args, .. } = &*sc {
                        let r = subst_n(&arms[0].body, args);
                        return walk(this, &r, k, d, fuel);
                    }
                    t.clone()
                }
                Term::App { rel: Rel::Irr, fun, .. } if matches!(&**fun, Term::Match { .. }) => {
                    let r = walk(this, fun, k, d, fuel);
                    if Rc::ptr_eq(&r, fun) { t.clone() } else { r }
                }
                // a projection of a `let`-bound pair (a slice built from
                // pieces, Σ3): its component
                Term::Fst(x) | Term::Snd(x) => {
                    let inner = match &**x {
                        Term::Var(Idx(i)) if *i >= k => match (d + k).checked_sub(1 + i).filter(|l| *l < d).and_then(|l| this.let_terms.get(&l).map(|def| (l, def))) {
                            Some((l, def)) if *fuel > 0 => {
                                *fuel -= 1;
                                shift(def, (d + k - l) as i64)
                            }
                            _ => return t.clone(),
                        },
                        _ => return t.clone(),
                    };
                    match &*inner {
                        Term::Pair { fst, snd, .. } => walk(this, if matches!(&**t, Term::Fst(_)) { fst } else { snd }, k, d, fuel),
                        // `fst(slice::mk T n l p)` is `n`
                        _ if matches!(&**t, Term::Fst(_)) => match head_app(&inner) {
                            Some((g, args)) if Some(g) == this.slice_mk && args.len() == 4 => walk(this, &args[1].1, k, d, fuel),
                            _ => t.clone(),
                        },
                        _ => t.clone(),
                    }
                }
                _ => t.clone(),
            }
        }
        walk(self, t, 0, d, &mut fuel)
    }

    /// Pushes a `let` (opaque in the evaluation view, definitional in the
    /// typing context).
    fn push_let(&mut self, e: &mut Engine<'_>, st: &mut St, name: &Rc<str>, rel: Rel, ty: &Tm, val: &Tm) -> W<()> {
        self.stats.lets += 1;
        if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
            eprintln!("opt: proof: let {name} ({:?}, |val| {}, heap {} MiB)", rel, crate::elab::tm::size_capped(val, 10_000_000), crate::memguard::allocated() >> 20);
        }
        let tyv = self.eval_full(e, st, ty)?;
        let lvl = st.depth();
        self.let_terms.insert(lvl, val.clone());
        if rel == Rel::Irr {
            self.fact_terms.insert(lvl, ty.clone());
        }
        match rel {
            Rel::Rel => {
                let full = self.eval_full(e, st, val)?;
                let entry = e.env.fresh_var(Lvl(lvl), Rel::Rel, &tyv);
                st.ctx = st.ctx.push(CtxEntry { name: name.clone(), rel, ty: tyv, def: Some(Arg::Rel(full)) });
                st.venv = venv_push(&st.venv, entry);
            }
            Rel::Irr => {
                let c = Closure { env: st.venv.clone(), body: val.clone() };
                st.ctx = st.ctx.push(CtxEntry { name: name.clone(), rel, ty: tyv, def: Some(Arg::Irr(c.clone())) });
                st.venv = venv_push(&st.venv, EnvEntry::Irr(c));
            }
        }
        Ok(())
    }

    /// Definitional head normalization of a source term (see the module
    /// docs); `let`s are not peeled here.
    fn whnf(&mut self, e: &mut Engine<'_>, st: &St, t: &Tm) -> W<Tm> {
        let mut t = t.clone();
        for _ in 0..256 {
            // a `let` variable at the head is its value (δ of the `let`)
            if let Term::Var(Idx(i)) = &*t
                && let Some(lvl) = st.depth().checked_sub(1 + i)
                && let Some(def) = self.let_terms.get(&lvl)
            {
                t = shift(def, (st.depth() - lvl) as i64);
                continue;
            }
            // `let x = v; x` is `v` (ζ)
            if let Term::Let { val, body, rel: Rel::Rel, .. } = &*t
                && matches!(&**body, Term::Var(Idx(0)))
            {
                t = val.clone();
                continue;
            }
            // β (as a `let`)
            if let Term::App { fun, arg, .. } = &*t
                && let Term::Lam { name, rel, dom, body } = &**fun
            {
                t = Rc::new(Term::Let { name: name.clone(), rel: *rel, ty: dom.clone(), val: arg.clone(), body: body.clone() });
                continue;
            }
            // ι: a head match whose scrutinee is (or evaluates to) a constructor
            if let Some(hm) = HeadMatch::of(&t) {
                // a `let` at the head of the (nested) scrutinee floats out
                // of the match first (ζ both ways): the source's `let`s are
                // pushed as definitional binders, never substituted (a
                // case-of-case source nests the callee's whole body, and
                // substituting its `let`s — or reading a constructor's
                // fields back through them — would copy every value,
                // proofs included, into each use)
                if let Some(t2) = float_let(&t) {
                    t = t2;
                    continue;
                }
                let ctor_args: Option<(u32, Vec<Tm>)> = match &*hm.scrut {
                    Term::Ctor { ctor, args, .. } => Some((*ctor, args.clone())),
                    _ => {
                        // fields read back from the evaluation view (small:
                        // `let`s opaque); the definitional view decides only
                        // field-less constructors
                        let v = self.eval(e, st, &hm.scrut)?;
                        match &*v {
                            Value::Ctor { ctor, args, .. } => {
                                let mut ts = Vec::new();
                                for a in args {
                                    ts.push(match a {
                                        Arg::Rel(x) => e.quote(st, x),
                                        Arg::Irr(c) => irr_tm(e, st, c),
                                    });
                                }
                                Some((*ctor, ts))
                            }
                            _ => {
                                // the definitional view: fields read back when small
                                let v = self.eval_full(e, st, &hm.scrut)?;
                                match &*v {
                                    Value::Ctor { ctor, args, .. } if args.is_empty() => Some((*ctor, vec![])),
                                    Value::Ctor { ctor, args, .. } => {
                                        let mut ts = Vec::new();
                                        let mut ok = true;
                                        for a in args {
                                            match a {
                                                Arg::Rel(x) => {
                                                    if crate::auto::meter::value_cost(e.env, &st.ctx, x, None, true, 20_001) > 20_000 {
                                                        ok = false;
                                                        break;
                                                    }
                                                    let q = e.env.quote_typed(&st.ctx, x, None, false);
                                                    ts.push(crate::auto::util::kernel_friendly(e.env, &q));
                                                }
                                                Arg::Irr(c) => ts.push(irr_tm(e, st, c)),
                                            }
                                        }
                                        ok.then_some((*ctor, ts))
                                    }
                                    _ => None,
                                }
                            }                        }
                    }
                };
                if let Some((k, args)) = ctor_args {
                    let Some(arm) = hm.arms.get(k as usize) else { return Ok(t) };
                    let b = subst_n(&arm.body, &args);
                    t = match hm.idiom {
                        Some(p) => mk::app_irr(b, p),
                        None => b,
                    };
                    continue;
                }
                // ζ/β inside the scrutinee (definitional; the scrutinee's
                // own `let`s are substituted)
                let mut sc = hm.scrut.clone();
                let mut changed = false;
                for _ in 0..16 {
                    match &*sc.clone() {
                        Term::Let { val, body, .. } => {
                            sc = crate::auto::util::subst0(body, val);
                            changed = true;
                        }
                        Term::App { fun, arg, .. } if matches!(&**fun, Term::Lam { .. }) => {
                            let Term::Lam { body, .. } = &**fun else { unreachable!() };
                            sc = crate::auto::util::subst0(body, arg);
                            changed = true;
                        }
                        // ι of a match on a constructor nested in the
                        // scrutinee (a case-of-case arm: the inner match's
                        // scrutinee was replaced by the arm's constructor)
                        _ if iota_inner(&sc).is_some() => {
                            sc = iota_inner(&sc).unwrap();
                            changed = true;
                        }
                        // δ of a transparent definition the driver unfolds
                        // (`!ok` is `bool::not ok`)
                        _ => match head_app(&sc) {
                            Some((g, args))
                                if e.env.global_opaque(g) == Some(false)
                                    && e.env.global_kind(g) != Some(DefKind::Intrinsic)
                                    && e.env.global_arity(g) == Some(args.len() as u32)
                                    && !e.is_recursive(g)
                                    && !self.folded.contains(&g) =>
                            {
                                match body_with_lets(e.env, g, &args.iter().map(|(_, a)| a.clone()).collect::<Vec<_>>(), self.outlined.get(&g).map(|o| &**o)) {
                                    Some(b) => {
                                        sc = b;
                                        changed = true;
                                    }
                                    None => break,
                                }
                            }
                            _ => break,
                        },
                    }
                }
                if changed {
                    t = hm.renormalized(sc);
                    continue;
                }
                return Ok(t);
            }
            // δ of a non-opaque, non-recursive definition at the head
            if let Some((g, args)) = head_app(&t)
                && e.env.global_opaque(g) == Some(false)
                && e.env.global_kind(g) != Some(DefKind::Intrinsic)
                && e.env.global_arity(g) == Some(args.len() as u32)
                && !e.is_recursive(g)
                && !self.folded.contains(&g)
            {
                match body_with_lets(e.env, g, &args.iter().map(|(_, a)| a.clone()).collect::<Vec<_>>(), self.outlined.get(&g).map(|o| &**o)) {
                    Some(b) => t = b,
                    None => return Ok(t),
                }
                continue;
            }
            // `fst`/`snd` of a pair
            if let Term::Fst(p) | Term::Snd(p) = &*t
                && let Term::Pair { fst, snd, .. } = &**p
            {
                t = if matches!(&*t, Term::Fst(_)) { fst.clone() } else { snd.clone() };
                continue;
            }
            return Ok(t);
        }
        Ok(t)
    }

    /// A proof of `g` in `st` following `node`.
    pub fn node(&mut self, e: &mut Engine<'_>, st: &St, g: Goal, node: &Node) -> W<Tm> {
        // the residual's `let`s (`let x = v; x` is `v`)
        if let Term::Let { val, body, rel: Rel::Rel, .. } = &*g.l
            && matches!(&**body, Term::Var(Idx(0)))
        {
            return self.node(e, st, Goal { l: val.clone(), ..g }, node);
        }
        if let Term::Let { name, rel, ty, val, body } = &*g.l {
            let mut st2 = st.clone();
            self.push_let(e, &mut st2, name, *rel, ty, val)?;
            let p = self.node(e, &st2, Goal { r: csh(&g.r, 1), l: body.clone(), s: csh(&g.s, 1) }, node)?;
            return Ok(Rc::new(Term::Let { name: name.clone(), rel: *rel, ty: ty.clone(), val: val.clone(), body: p }));
        }
        // a large residual side under source-side steps: bound once by a
        // `let` (definitional), so the steps' motives mention its variable
        // instead of copying it (it is materialized again where the tree
        // splits it, [`Walk::real_l`])
        if !node.steps.is_empty() && crate::elab::tm::size_capped(&g.l, LET_L_NODES + 1) > LET_L_NODES {
            let mut st2 = st.clone();
            let name: Rc<str> = Rc::from("lres");
            self.push_let(e, &mut st2, &name, Rel::Rel, &g.r, &g.l)?;
            let p = self.after_step(e, &st2, Goal { r: csh(&g.r, 1), l: mk::var(0), s: csh(&g.s, 1) }, node, 0)?;
            return Ok(Rc::new(Term::Let { name, rel: Rel::Rel, ty: g.r.clone(), val: g.l.clone(), body: p }));
        }
        self.after_step(e, st, g, node, 0)
    }

    /// The residual side `l` with a `let` variable of [`Walk::node`]'s
    /// residual binding replaced by its value (shifted to `st`'s depth).
    fn real_l(&self, st: &St, l: &Tm) -> Tm {
        if let Term::Var(Idx(i)) = &**l
            && let Some(lvl) = st.depth().checked_sub(1 + i)
            && st.ctx.entries.get(lvl as usize).is_some_and(|en| en.name.as_ref() == "lres")
            && let Some(v) = self.let_terms.get(&lvl)
        {
            return csh(v, (st.depth() - lvl) as i64);
        }
        l.clone()
    }

    /// The source's `let`s and head normalization, then the steps from `i`.
    fn after_step(&mut self, e: &mut Engine<'_>, st: &St, g: Goal, node: &Node, i: usize) -> W<Tm> {
        let s = self.whnf(e, st, &g.s)?;
        if let Term::Let { name, rel, ty, val, body } = &*s {
            let mut st2 = st.clone();
            self.push_let(e, &mut st2, name, *rel, ty, val)?;
            let p = self.after_step(e, &st2, Goal { r: csh(&g.r, 1), l: csh(&g.l, 1), s: body.clone() }, node, i)?;
            return Ok(Rc::new(Term::Let { name: name.clone(), rel: *rel, ty: ty.clone(), val: val.clone(), body: p }));
        }
        let g = Goal { s, ..g };
        if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
            eprintln!(
                "opt: proof: node depth {} step {i}/{} (proof depth {}): |L| {} |S| {} heap {} MiB steps left {}",
                node.depth,
                node.steps.len(),
                st.depth(),
                crate::elab::tm::size_capped(&g.l, 10_000_000),
                crate::elab::tm::size_capped(&g.s, 10_000_000),
                crate::memguard::allocated() >> 20,
                e.b.steps
            );
        }
        let Some(step) = node.steps.get(i) else { return self.head(e, st, g, node) };
        // a leaf's polyvariant specializations: rewritten when the leaf is
        // closed (the helpers' calls in the residual, `leaf_helpers`)
        if let Step::SpecializeIn { .. } | Step::Fold { .. } | Step::Seq | Step::Demand = step {
            return self.after_step(e, st, g, node, i + 1);
        }
        match self.step(e, st, &g, step)? {
            Some((g2, w)) => {
                self.stats.steps_applied += 1;
                // the continuation is built under the wrap's equation binder
                // (pushed now: no shift of the continuation's proof) and, when
                // the new source's match carries a proof history as its
                // idiom argument, under an `Irr` `let` of that proof (the
                // source stays small, and so does every motive copying it)
                let mut st2 = st.clone();
                let mut g2 = g2;
                if let Some(dom) = &w.e_dom {
                    let lvl = st2.depth();
                    let tv = self.eval_full(e, st, dom)?;
                    st2.push_raw(e.env, Rc::from("e"), Rel::Irr, tv);
                    self.fact_terms.insert(lvl, dom.clone());
                    g2 = Goal { r: csh(&g2.r, 1), l: csh(&g2.l, 1), s: csh(&g2.s, 1) };
                }
                let mut hist: Option<(Rc<str>, Tm, Tm)> = None;
                if let Some(hm) = HeadMatch::of(&g2.s)
                    && let Some(q) = &hm.idiom
                    && !matches!(&**q, Term::Var(_) | Term::Refl { .. })
                    && let Some(s0) = idiom_scrut(&hm)
                {
                    let ty = mk::eq(mk::ind(hm.ind, hm.params.clone()), s0, hm.scrut.clone());
                    let name: Rc<str> = Rc::from("hist");
                    self.push_let(e, &mut st2, &name, Rel::Irr, &ty, q)?;
                    let hm1 = hm.shifted(1);
                    let s_new = hm1.rebuild(0, hm1.scrut.clone(), Some(mk::var(0)));
                    hist = Some((name, ty, q.clone()));
                    g2 = Goal { r: csh(&g2.r, 1), l: csh(&g2.l, 1), s: s_new };
                }
                let mut p = self.after_step(e, &st2, g2, node, i + 1)?;
                if let Some((name, ty, val)) = hist {
                    p = Rc::new(Term::Let { name, rel: Rel::Irr, ty, val, body: p });
                }
                Ok(w.apply_bound(p))
            }
            None => {
                self.stats.steps_absent += 1;
                self.after_step(e, st, g, node, i + 1)
            }
        }
    }

    /// One step on the source's head: the new source term and the wrap.
    fn step(&mut self, e: &mut Engine<'_>, st: &St, g: &Goal, s: &Step) -> W<Option<(Goal, Wrap)>> {
        match s {
            Step::Unfold { def, .. } => {
                // the application: the whole head, or the head match's scrutinee
                let hm = HeadMatch::of(&g.s);
                let app = match &hm {
                    Some(hm) => hm.scrut.clone(),
                    None => g.s.clone(),
                };
                let Some((h, args)) = head_app(&app) else { return Ok(None) };
                if h != *def || e.env.global_arity(h) != Some(args.len() as u32) {
                    return Ok(None);
                }
                let arg_tms = self.reproved_args(e, st, *def, &args);
                let delta: Tm = Rc::new(Term::Delta { def: *def, args: arg_tms.clone() });
                let tr = std::env::var_os("SANDBLASTER_OPT_TRACE").is_some();
                if tr {
                    eprintln!("opt: proof: unfold {}: args {:?}", e.env.global_name(*def).unwrap_or_default(), arg_tms.iter().map(|a| crate::elab::tm::size_capped(a, 10_000_000)).collect::<Vec<_>>());
                }
                e.settle();
                let ty = e.env.infer(&st.ctx, &delta, e.b).map_err(|err| format!("`Delta({})` does not check: {}", e.env.global_name(*def).unwrap_or_default(), err.to_string().chars().take(300).collect::<String>()))?;
                let Some(rt) = crate::auto::util::as_eq(&ty).map(|(a, _, _)| a.clone()) else { return Err("`Delta` is not an equation".into()) };
                if tr {
                    eprintln!("opt: proof: unfold: Delta inferred (heap {} MiB)", crate::memguard::allocated() >> 20);
                }
                let a_tm = e.quote(st, &rt);
                let unfolded = body_with_lets(e.env, *def, &arg_tms, self.outlined.get(def).map(|o| &**o)).ok_or("a body without its parameter λs")?;
                Ok(Some(with_source(g, rewrite_head(st, g, hm.as_ref(), a_tm, app, unfolded, delta))))
            }
            Step::Prune { value, .. } => {
                let Some((s_exp, hm, inner)) = self.head_decision(&g.s, st.depth()) else { return Ok(None) };
                let c_tm = inner.clone().unwrap_or_else(|| hm.scrut.clone());
                // the condition with its bit-level `let`s expanded (a
                // varint's accumulated value is a chain of `let`s the
                // evaluation view keeps opaque): the decision reads the
                // operations, its atoms stay the `let` variables of the
                // element reads; convertible with the condition (δ)
                let c_x = self.expand_bit_lets(&c_tm, st.depth(), 64);
                if std::env::var_os("SANDBLASTER_OPT_TRACE_SPLITS").is_some() {
                    let names = st.names();
                    eprintln!("opt: proof: prune condition {} expanded {}", e.env.print_term(&names, &c_tm).chars().take(200).collect::<String>(), e.env.print_term(&names, &c_x).chars().take(300).collect::<String>());
                }
                let c = self.eval(e, st, &c_x)?;
                self.cond_tm = Some(c_x.clone());
                // as the driver decided it: over generalized leaves when the
                // condition has the shape
                // (a simulated fault's claim need not be derivable: the
                // trusted builder states it and the kernel judges it)
                let r = match self.replay_decision(e, st, &c) {
                    Ok(r) => r,
                    Err(_) if self.trust => None,
                    Err(why) => return Err(why),
                };
                let (b, p) = match r {
                    Some((b, p)) if b == *value => (b, p),
                    // a trusted claim: the kernel's linarith check decides it
                    _ if self.trust => (*value, Rc::new(Term::Linarith { hyps: vec![], goal: mk::eq_bool(e.n.bool_ind, c_tm.clone(), *value), cert: vec![] })),
                    None => return Err("a pruned condition that linear arithmetic does not decide in the proof".into()),
                    Some(_) => return Err("a pruned condition decided the other way".into()),
                };
                let lit = mk::bool_lit(e.n.bool_ind, b);
                let a_tm = mk::bool_ty(e.n.bool_ind);
                match inner {
                    None => Ok(Some(with_source(g, rewrite_head(st, g, Some(&hm), a_tm, c_tm, lit, p)))),
                    Some(_) => {
                        let bt: V = Rc::new(Value::Ind { ind: e.n.bool_ind, params: vec![] });
                        self.rewrite_abs(e, st, &Goal { s: s_exp, ..g.clone() }, &bt, a_tm, c_tm, lit, p).map(Some)
                    }
                }
            }
            Step::Specialize { def, key } => {
                // the application: the whole head, or the head match's scrutinee
                let hm = HeadMatch::of(&g.s);
                let app = match &hm {
                    Some(hm) => hm.scrut.clone(),
                    None => g.s.clone(),
                };
                let Some((h, args)) = head_app(&app) else { return Ok(None) };
                if h != *def {
                    return Ok(None);
                }
                let info = *self.specs.get(key).ok_or("a specialization without its helper")?;
                // the dynamic relevant arguments, in order
                let statics: Vec<usize> = key.statics.iter().map(|(i, _)| *i).collect();
                let dyn_args: Vec<(Rel, Tm)> = args.iter().enumerate().filter(|(i, (rel, _))| *rel == Rel::Rel && !statics.contains(i)).map(|(_, a)| a.clone()).collect();
                let to = mk::apps(mk::global(info.helper), dyn_args.clone());
                // lemma dyn̄ : Eq(R, h dyn̄, def(statics, dyn̄)), and `app` is that
                // application by conversion (literal arguments, proofs irrelevant)
                let inst = mk::apps(mk::global(info.lemma), dyn_args);
                let e_ty = e.env.infer(&st.ctx, &inst, e.b).map_err(|err| format!("a helper lemma instance does not check: {}", err.to_string().chars().take(300).collect::<String>()))?;
                let Some(rt) = crate::auto::util::as_eq(&e_ty).map(|(a, _, _)| a.clone()) else { return Err("a helper lemma that is not an equation".into()) };
                let a_tm = e.quote(st, &rt);
                let p = sym_tm(&a_tm, &to, &app, &inst);
                Ok(Some(with_source(g, rewrite_head(st, g, hm.as_ref(), a_tm, app, to, p))))
            }
            Step::Word { blocks, .. } => {
                // the comparison: the whole head, or the head match's scrutinee
                let hm = HeadMatch::of(&g.s);
                let app = match &hm {
                    Some(hm) => hm.scrut.clone(),
                    None => g.s.clone(),
                };
                let Some(w) = crate::opt::drive::word::WordIds::new(e.env) else { return Err("the word lemmas are not loaded".into()) };
                let Some((h, args)) = head_app(&app) else { return Ok(None) };
                if h != w.seq_eq || args.len() != 4 {
                    return Ok(None);
                }
                // the elements as `seq::index T xs i` of the source's lists
                let (t, xs, ys) = (args[0].1.clone(), args[2].1.clone(), args[3].1.clone());
                let elem = |side: usize, i: usize| w.index_tm(&t, if side == 0 { &xs } else { &ys }, i);
                let m = *blocks as usize;
                let to = w.form(&elem, m);
                // P : Eq(Bool, to, seq::eq U8 (==) [a₀, …] [b₀, …]), and `app`
                // is that comparison (conversion)
                let pf = w.proof(&elem, m);
                let bool_tm = mk::bool_ty(e.n.bool_ind);
                let p = sym_tm(&bool_tm, &to, &app, &pf);
                e.settle();
                e.env.infer(&st.ctx, &p, e.b).map_err(|err| format!("the word-form lemmas do not apply: {}", err.to_string().chars().take(300).collect::<String>()))?;
                Ok(Some(with_source(g, rewrite_head(st, g, hm.as_ref(), bool_tm, app, to, p))))
            }
            Step::Link { def, res, lemma, .. } => {
                // the application: the whole head, or the head match's scrutinee
                let hm = HeadMatch::of(&g.s);
                let app = match &hm {
                    Some(hm) => hm.scrut.clone(),
                    None => g.s.clone(),
                };
                let Some((h, args)) = head_app(&app) else { return Ok(None) };
                if h != *def || e.env.global_arity(h) != Some(args.len() as u32) {
                    return Ok(None);
                }
                // lemma ā : Eq(R, res ā, def ā); R is the callee's result at ā
                let tele = crate::opt::symex::telescope(e.env, *def).ok_or("a linked callee without a telescope")?;
                let arg_tms: Vec<Tm> = args.iter().map(|(_, a)| a.clone()).collect();
                let a_tm = subst_n(&tele.ret, &arg_tms);
                let to = mk::apps(mk::global(*res), args.clone());
                let inst = mk::apps(mk::global(*lemma), args);
                let p = sym_tm(&a_tm, &to, &app, &inst);
                Ok(Some(with_source(g, rewrite_head(st, g, hm.as_ref(), a_tm, app, to, p))))
            }
            Step::Fold { .. } | Step::Seq | Step::Demand => Ok(None),
            // handled at the leaf (`leaf_helpers`, `fold_back`)
            Step::SpecializeIn { .. } => Ok(None),
            Step::Checked { def, value } => {
                // the call is the head match's scrutinee
                let Some(hm) = HeadMatch::of(&g.s) else { return Ok(None) };
                let app = hm.scrut.clone();
                let Some((h, args)) = head_app(&app) else { return Ok(None) };
                if h != *def {
                    return Ok(None);
                }
                let name = e.env.global_name(*def).unwrap_or_default();
                let lemma = e.env.lookup_global(&format!("{name}_{}", if *value { "some" } else { "none" })).ok_or("a checked-arithmetic lemma that is not loaded")?;
                let rel: Vec<Tm> = args.iter().filter(|(r, _)| *r == Rel::Rel).map(|(_, a)| a.clone()).collect();
                if rel.len() != 2 {
                    return Ok(None);
                }
                // the condition: the lemma's hypothesis at the arguments
                let Some(lty) = e.env.global_type(lemma) else { return Ok(None) };
                let Term::Pi { cod: c1, .. } = &*lty else { return Ok(None) };
                let Term::Pi { cod: c2, .. } = &**c1 else { return Ok(None) };
                let Term::Pi { dom: hyp, .. } = &**c2 else { return Ok(None) };
                let hyp = subst_n(hyp, &rel);
                let Term::Eq { lhs: c_tm, .. } = &*hyp else { return Ok(None) };
                let c = self.eval(e, st, c_tm)?;
                let r = match self.replay_decision(e, st, &c) {
                    Ok(r) => r,
                    Err(_) if self.trust => None,
                    Err(why) => return Err(why),
                };
                let p = match r {
                    Some((b, p)) if b == *value => p,
                    _ if self.trust => Rc::new(Term::Linarith { hyps: vec![], goal: mk::eq_bool(e.n.bool_ind, c_tm.clone(), *value), cert: vec![] }),
                    None => return Err("a checked-arithmetic condition that linear arithmetic does not decide in the proof".into()),
                    Some(_) => return Err("a checked-arithmetic condition decided the other way".into()),
                };
                let inst = mk::apps(mk::global(lemma), [(Rel::Rel, rel[0].clone()), (Rel::Rel, rel[1].clone()), (Rel::Irr, p)]);
                e.settle();
                let e_ty = e.env.infer(&st.ctx, &inst, e.b).map_err(|err| format!("a checked-arithmetic lemma instance does not check: {}", err.to_string().chars().take(300).collect::<String>()))?;
                let Some((a_v, _, to_v)) = crate::auto::util::as_eq(&e_ty).map(|(a, l, r)| (a.clone(), l.clone(), r.clone())) else { return Err("a checked-arithmetic lemma that is not an equation".into()) };
                let a_tm = e.quote(st, &a_v);
                let to = e.quote(st, &to_v);
                Ok(Some(with_source(g, rewrite_head(st, g, Some(&hm), a_tm, app, to, inst))))
            }
            Step::LoopSum { def, key } => {
                // the application: the whole head, or the head match's scrutinee
                let hm = HeadMatch::of(&g.s);
                let app = match &hm {
                    Some(hm) => hm.scrut.clone(),
                    None => g.s.clone(),
                };
                let Some((h, args)) = head_app(&app) else { return Ok(None) };
                if h != *def {
                    return Ok(None);
                }
                let lh = crate::opt::loopsum::helper(key).ok_or("a loop summary without its helper")?;
                // the helper's arguments: the application's dynamic relevant
                // ones, then its `requires` proven here
                let statics: Vec<usize> = key.statics.iter().map(|(i, _)| *i).collect();
                let tele = crate::opt::symex::telescope(e.env, lh.global).ok_or("a loop helper without a telescope")?;
                let mut rel = args.iter().filter(|(r, _)| *r == Rel::Rel).enumerate().filter(|(i, _)| !statics.contains(i)).map(|(_, (_, a))| a.clone());
                let mut full: Vec<(Rel, Tm)> = Vec::new();
                let mut vals: Vec<EnvEntry> = Vec::new();
                for (_, r, dom) in &tele.binders {
                    e.settle();
                    match r {
                        Rel::Rel => {
                            let a = rel.next().ok_or("a loop call with too few arguments")?;
                            vals.push(EnvEntry::Rel(self.eval_full(e, st, &a)?));
                            full.push((Rel::Rel, a));
                        }
                        Rel::Irr => {
                            let goal = e.env.eval(&VEnv(Rc::new(vals.clone())), Lvl(st.depth()), dom, e.b).map_err(|err| format!("a loop helper's requires: {err:?}"))?;
                            let p = match e.solve(st, goal, true) {
                                Ok(Some(p)) => p,
                                _ => return Err("the loop helper's requires is not proven at the call".into()),
                            };
                            vals.push(EnvEntry::Irr(Closure { env: st.venv.clone(), body: p.clone() }));
                            full.push((Rel::Irr, p));
                        }
                    }
                }
                let to = mk::apps(mk::global(lh.global), full.clone());
                // link d̄ h̄ : Eq(R, H d̄ h̄, def(statics, d̄) h̄), and `app` is that
                // application by conversion (literal arguments, proofs irrelevant)
                let inst = mk::apps(mk::global(lh.lemma), full);
                let e_ty = e.env.infer(&st.ctx, &inst, e.b).map_err(|err| format!("a loop helper's link does not check: {}", err.to_string().chars().take(300).collect::<String>()))?;
                let Some(rt) = crate::auto::util::as_eq(&e_ty).map(|(a, _, _)| a.clone()) else { return Err("a loop link that is not an equation".into()) };
                let a_tm = e.quote(st, &rt);
                let p = sym_tm(&a_tm, &to, &app, &inst);
                Ok(Some(with_source(g, rewrite_head(st, g, hm.as_ref(), a_tm, app, to, p))))
            }
            Step::GuardSpec { def, key } => {
                // the application: the whole head (a tail call)
                let hm = HeadMatch::of(&g.s);
                let app = match &hm {
                    Some(hm) => hm.scrut.clone(),
                    None => g.s.clone(),
                };
                let Some((h, args)) = head_app(&app) else { return Ok(None) };
                if h != *def {
                    return Ok(None);
                }
                e.settle();
                let (to, inst) = {
                    let env = e.env;
                    let lets = |l: u32| self.let_terms.get(&l).and_then(|t| crate::opt::facts::folded_call(env, st, l, t));
                    crate::opt::guardspec::call_site(env, st, key, &args, &lets)?
                };
                let e_ty = e.env.infer(&st.ctx, &inst, e.b).map_err(|err| format!("a guard helper's lemma instance does not check: {}", err.to_string().chars().take(300).collect::<String>()))?;
                let Some(rt) = crate::auto::util::as_eq(&e_ty).map(|(a, _, _)| a.clone()) else { return Err("a guard helper's lemma that is not an equation".into()) };
                let a_tm = e.quote(st, &rt);
                let p = sym_tm(&a_tm, &to, &app, &inst);
                Ok(Some(with_source(g, rewrite_head(st, g, hm.as_ref(), a_tm, app, to, p))))
            }
            Step::FoldCall { def } => {
                // the application: the whole head, or the head match's scrutinee
                let hm = HeadMatch::of(&g.s);
                let app = match &hm {
                    Some(hm) => hm.scrut.clone(),
                    None => g.s.clone(),
                };
                let Some((h, args)) = head_app(&app) else { return Ok(None) };
                if h != *def {
                    return Ok(None);
                }
                let (helper, lemma) = *self.folds.get(def).ok_or("a fold call without its helper")?;
                // the helper's arguments: the application's relevant ones,
                // then its `requires` (the source's and the bound
                // invariant) proven here
                let tele = crate::opt::symex::telescope(e.env, helper).ok_or("a fold helper without a telescope")?;
                let mut rel = args.iter().filter(|(r, _)| *r == Rel::Rel).map(|(_, a)| a.clone());
                let mut full: Vec<(Rel, Tm)> = Vec::new();
                let mut vals: Vec<EnvEntry> = Vec::new();
                for (_, r, dom) in &tele.binders {
                    e.settle();
                    match r {
                        Rel::Rel => {
                            let a = rel.next().ok_or("a fold call with too few arguments")?;
                            vals.push(EnvEntry::Rel(self.eval_full(e, st, &a)?));
                            full.push((Rel::Rel, a));
                        }
                        Rel::Irr => {
                            let goal = e.env.eval(&VEnv(Rc::new(vals.clone())), Lvl(st.depth()), dom, e.b).map_err(|err| format!("a fold helper's requires: {err:?}"))?;
                            let p = match e.solve(st, goal, true) {
                                Ok(Some(p)) => p,
                                _ => return Err("the fold helper's requires (its bound invariant) is not proven at the call".into()),
                            };
                            vals.push(EnvEntry::Irr(Closure { env: st.venv.clone(), body: p.clone() }));
                            full.push((Rel::Irr, p));
                        }
                    }
                }
                let to = mk::apps(mk::global(helper), full.clone());
                // lemma x̄ h : Eq(R, H x̄ h, E x̄ h), and the entry `E x̄ h`
                // is the application by definition (δ, proofs irrelevant)
                let inst = mk::apps(mk::global(lemma), full);
                let e_ty = e.env.infer(&st.ctx, &inst, e.b).map_err(|err| format!("a fold lemma instance does not check: {}", err.to_string().chars().take(300).collect::<String>()))?;
                let Some(rt) = crate::auto::util::as_eq(&e_ty).map(|(a, _, _)| a.clone()) else { return Err("a fold lemma that is not an equation".into()) };
                let a_tm = e.quote(st, &rt);
                let p = sym_tm(&a_tm, &to, &app, &inst);
                Ok(Some(with_source(g, rewrite_head(st, g, hm.as_ref(), a_tm, app, to, p))))
            }
            Step::Reuse { eq, flip, .. } => {
                let Some((s_exp, hm, inner)) = self.head_decision(&g.s, st.depth()) else { return Ok(None) };
                let pl = *self.lvl.get(eq).ok_or("a reused path equation out of scope")?;
                let entry = st.ctx.entries.get(pl as usize).ok_or("a reused path equation out of scope")?;
                let Value::Eq { ty, rhs, .. } = &*entry.ty.clone() else { return Err("a reused path equation that is not an equation".into()) };
                let a_tm = e.quote(st, ty);
                let mut to = e.quote(st, rhs);
                if *flip {
                    // a trusted claim (fault R13): the other constructor, with
                    // this arm's equation as its proof
                    to = match &*to {
                        Term::Ctor { ctor, .. } => mk::bool_lit(e.n.bool_ind, *ctor == 0),
                        _ => to,
                    };
                }
                match inner {
                    None => {
                        let scrut = hm.scrut.clone();
                        Ok(Some(with_source(g, rewrite_head(st, g, Some(&hm), a_tm, scrut, to, st.var(pl)))))
                    }
                    Some(c_tm) => self.rewrite_abs(e, st, &Goal { s: s_exp, ..g.clone() }, ty, a_tm, c_tm, to, st.var(pl)).map(Some),
                }
            }
        }
    }

    /// A decision of the driver replayed on the source's condition value
    /// `c` (as the driver asked it: over the facts whose bounds decide it,
    /// generalized leaves when it has the shape), in its own meter scope and
    /// within [`DECISION_STEPS`] of the proof's budget: a limit it hits ends
    /// this decision only, and a proof holding a placeholder of a refused
    /// read-back is no decision.
    fn replay_decision(&mut self, e: &mut Engine<'_>, st: &St, c: &V) -> W<Option<(bool, Tm)>> {
        // plan O6: with the facts of the path's kept calls, as the driver
        // decided (`opt::facts::with_imports`)
        // (and §15 S2: the invariants of the values it tests)
        let st2 = {
            let env = e.env;
            let lets = |l: u32| self.let_terms.get(&l).and_then(|t| crate::opt::facts::folded_call(env, st, l, t));
            crate::opt::facts::with_decision_facts(env, st, c, &lets)
        };
        if let Some(st2) = st2 {
            return Ok(self.replay_decision_in(e, &st2, c)?.map(|(b, p)| (b, crate::opt::facts::close(&st2, p))));
        }
        self.replay_decision_in(e, st, c)
    }

    fn replay_decision_in(&mut self, e: &mut Engine<'_>, st: &St, c: &V) -> W<Option<(bool, Tm)>> {
        use crate::opt::drive::facts::{decidable_with, Decidable};
        e.settle();
        let before = e.b.steps;
        let cap = before.min(DECISION_STEPS);
        e.b.steps = cap;
        let r = {
            let _scope = crate::auto::meter::Scope::enter(None, e.b);
            // (the driver decided it: when the proof's facts — the
            // residual's path equations, which may state a joined condition
            // where the driver split its parts — do not decide it by
            // intervals, the query gets every fact)
            let c_tm = self.cond_tm.take();
            let r = match decidable_with(st, c) {
                (Decidable::ByIntervals, used) => match crate::opt::drive::facts::decide_generalized_at(e, st, c, c_tm.as_ref(), &used, true) {
                    Some(d) => Ok(Some(d)),
                    None => e.decide_bool(st, c),
                },
                _ => e.decide_bool(st, c),
            };
            crate::auto::meter::settle(e.b);
            r
        };
        let used = cap - e.b.steps.min(cap);
        e.b.steps = before - used;
        e.settle();
        if std::env::var_os("SANDBLASTER_OPT_TRACE_SPLITS").is_some() {
            eprintln!("opt: proof: replayed decision {:?} ({used} steps) on {}", r.as_ref().map(|x| x.as_ref().map(|(b, _)| *b)).map_err(|_| ()), e.show(st, c).chars().take(400).collect::<String>());
        }
        match r {
            Ok(Some((b, p))) if !crate::elab::tm::any_node(&p, &mut |n| matches!(n, Term::Erased)) => Ok(Some((b, p))),
            Ok(_) => Ok(None),
            Err(_) => Err("the budget is exhausted".into()),
        }
    }

    /// The decision point of the source's head: its head match, and — when
    /// its scrutinee is a `let`-bound or nested condition (`a && b`) — the
    /// exposed source and the innermost scrutinee (the one the driver
    /// decided).
    fn head_decision(&self, s: &Tm, d: u32) -> Option<(Tm, HeadMatch, Option<Tm>)> {
        let hm = HeadMatch::of(s)?;
        if HeadMatch::of(&hm.scrut).is_none() && !matches!(&*hm.scrut, Term::Var(_)) {
            return Some((s.clone(), hm, None));
        }
        let mut s2 = s.clone();
        for _ in 0..4 {
            match self.expose(&s2, d) {
                Some(t) => s2 = t,
                None => break,
            }
        }
        let hm2 = HeadMatch::of(&s2)?;
        let mut inner = hm2.scrut.clone();
        let mut nested = false;
        while let Some(im) = HeadMatch::of(&inner) {
            inner = im.scrut.clone();
            nested = true;
        }
        if !nested {
            // an exposed variable: its value's own head decides
            return Some((s2, hm2, None));
        }
        Some((s2.clone(), hm2, Some(inner)))
    }

    /// Rewrites `from` (anywhere in the goal) to `to` with `p : Eq(A, from,
    /// to)` through a motive built by `auto`'s abstraction (checked).
    #[allow(clippy::too_many_arguments)]
    fn rewrite_abs(&mut self, e: &mut Engine<'_>, st: &St, g: &Goal, a: &V, a_tm: Tm, f_tm: Tm, to: Tm, p: Tm) -> W<(Goal, Wrap)> {
        let from_v = self.eval_full(e, st, &f_tm)?;
        // the source side only (the residual does not change)
        let Some((s_body, uses_e, blind)) = super::steps::abstract_source(e, st, &g.r, &g.s, &f_tm, &a_tm, &from_v, &self.fact_terms) else { return Err("a decided condition that does not occur in the source".into()) };
        let body = mk::eq(csh(&g.r, 2), csh(&g.l, 2), s_body);
        let has_e = uses_e > 0;
        let m = if has_e { mk::pi("e", Rel::Irr, mk::eq(shift(&a_tm, 1), shift(&f_tm, 1), mk::var(0)), body.clone()) } else { shift_from(&body, -1, 1) };
        let m = super::steps::check_motive(e, st, a, m, blind)?;
        let new_tm = super::steps::inst2(&body, &to, &p, 0);
        let Term::Eq { ty: r2, lhs: l2, rhs: s2 } = &*new_tm else { return Err("a rewritten goal that is not an equation".into()) };
        let eq = sym_tm(&a_tm, &f_tm, &to, &p);
        let e_dom = has_e.then(|| mk::eq(a_tm.clone(), f_tm.clone(), to.clone()));
        Ok((Goal { r: r2.clone(), l: l2.clone(), s: s2.clone() }, Wrap { depth: st.depth(), ty: a_tm, lhs: to, rhs: f_tm, eq, motive: m, e_dom }))
    }

    /// The arguments of an unfolded application, each proof argument
    /// re-proven in the current context when `auto` can (a proof carried
    /// over from the source mentions every fact of its own context, and
    /// with the source's parameters bound to unrolled values its linarith
    /// atoms grow at every level; a fresh proof mentions what it needs).
    fn reproved_args(&mut self, e: &mut Engine<'_>, st: &St, def: GlobalId, args: &[(Rel, Tm)]) -> Vec<Tm> {
        let mut out: Vec<Tm> = args.iter().map(|(_, a)| a.clone()).collect();
        let Some(mut ty) = e.env.global_type(def) else { return out };
        let mut vals: Vec<EnvEntry> = Vec::new();
        for (i, (rel, a)) in args.iter().enumerate() {
            let Term::Pi { dom, cod, .. } = &*ty.clone() else { return out };
            if *rel == Rel::Irr {
                e.settle();
                let env_i = VEnv(Rc::new(vals.clone()));
                let goal = e.env.eval(&env_i, Lvl(st.depth()), dom, e.b);
                if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
                    eprintln!("opt: proof: re-proving argument {i} of {}: {}", e.env.global_name(def).unwrap_or_default(), goal.as_ref().map(|g| e.show(st, g)).unwrap_or_default().chars().take(300).collect::<String>());
                }
                if let Ok(goal) = goal
                    && let Ok(Some(p)) = e.solve(st, goal, true)
                {
                    out[i] = p;
                    if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
                        eprintln!("opt: proof: re-proven ({} nodes)", crate::elab::tm::size_capped(&out[i], 1_000_000));
                    }
                }
                vals.push(EnvEntry::Irr(Closure { env: st.venv.clone(), body: out[i].clone() }));
            } else {
                match self.eval_full(e, st, a) {
                    Ok(v) => vals.push(EnvEntry::Rel(v)),
                    Err(_) => return out,
                }
            }
            ty = cod.clone();
        }
        out
    }

    /// The source with its head match's scrutinee — or the innermost
    /// scrutinee of a nested condition (`match (match ok ..) ..`) — a `let`
    /// variable, replaced by the `let`'s value (definitionally equal).
    fn expose(&self, s: &Tm, d: u32) -> Option<Tm> {
        let hm = HeadMatch::of(s)?;
        if HeadMatch::of(&hm.scrut).is_some() {
            // a nested condition: expose inside the scrutinee (its own idiom
            // arguments keep their types: the scrutinee's value is
            // definitionally the same)
            let inner = self.expose(&hm.scrut, d)?;
            return Some(hm.renormalized(inner));
        }
        let Term::Var(Idx(i)) = &*hm.scrut else { return None };
        let lvl = d.checked_sub(1 + i)?;
        let def = shift(self.let_terms.get(&lvl)?, (d - lvl) as i64);
        // the idiom's `refl(D, x)` becomes `refl(D, v)`, so abstraction sees
        // the scrutinee in it (and transports it)
        let arg = match &hm.idiom {
            Some(a) => match &**a {
                Term::Refl { ty, val } if matches!(&**val, Term::Var(Idx(j)) if j == i) => Some(mk::refl(ty.clone(), def.clone())),
                _ => Some(a.clone()),
            },
            None => None,
        };
        Some(hm.rebuild(0, def, arg))
    }

    /// Conversion, else a split like the tree, else `auto`.
    fn head(&mut self, e: &mut Engine<'_>, st: &St, g: Goal, node: &Node) -> W<Tm> {
        if let NodeKind::Bind { lvl, name, value, body, .. } = &node.kind {
            return self.bind(e, st, g, *lvl, name, value, body);
        }
        // a fold helper's back-edge: its induction hypothesis
        if matches!(node.kind, NodeKind::Leaf(_))
            && let Some(Step::Fold { .. }) = node.steps.last()
        {
            return self.fold_back(e, st, &g);
        }
        let d = st.depth();
        let lv = self.eval_full(e, st, &g.l)?;
        let sv = self.eval_full(e, st, &g.s)?;
        e.settle();
        // (a Σ3 leaf is proven by its normal form even when trusting: the
        // R5 fault is in that proof)
        let seq_leaf = node.steps.iter().any(|s| matches!(s, Step::Seq));
        if e.env.conv(Lvl(d), &lv, &sv, e.b).unwrap_or(false) || (self.trust && matches!(node.kind, NodeKind::Leaf(_)) && !seq_leaf) {
            self.stats.leaves_refl += 1;
            return Ok(mk::refl(g.r.clone(), g.l.clone()));
        }
        match &node.kind {
            NodeKind::Bind { .. } => unreachable!(),
            // Σ3: the residual's own test (a demand split)
            NodeKind::Split { ind, arms, .. } if node.steps.iter().any(|s| matches!(s, Step::Demand)) => {
                self.stats.splits += 1;
                self.demand_split(e, st, g, *ind, arms)
            }
            // Σ3: a leaf by the segment normal form
            NodeKind::Leaf(_) if node.steps.iter().any(|s| matches!(s, Step::Seq)) => {
                let l = self.real_l(st, &g.l);
                let cx = crate::opt::seqsum::prove::LeafCtx { res: self.res, own: self.own_fold.as_ref(), folds: &self.folds, let_terms: &self.let_terms };
                let r = crate::opt::seqsum::prove::leaf(&cx, e, st, &g.r, &l, &g.s);
                if let Err(why) = &r
                    && std::env::var_os("SANDBLASTER_OPT_TRACE").is_some()
                {
                    eprintln!("opt: proof: seq leaf: {why}");
                }
                self.stats.leaves_auto += 1;
                r
            }
            NodeKind::Split { ind, arms, merged: Some(_), .. } => {
                self.stats.splits += 1;
                self.split_source(e, st, g, *ind, arms)
            }
            NodeKind::Split { ind, arms, .. } => {
                self.stats.splits += 1;
                self.split(e, st, g, *ind, arms)
            }
            NodeKind::Leaf(_) => {
                if let Some(p) = self.leaf_helpers(e, st, &g, &lv, &sv)? {
                    self.stats.leaves_refl += 1;
                    return Ok(p);
                }
                self.stats.leaves_auto += 1;
                if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
                    let names = st.names();
                    let cut = |s: String| s.chars().take(2000).collect::<String>();
                    eprintln!("opt: proof: leaf not convertible\n  L = {}\n  S = {}\n  L* = {}\n  S* = {}", cut(e.env.print_term(&names, &g.l)), cut(e.env.print_term(&names, &g.s)), e.show(st, &lv), e.show(st, &sv));
                }
                let rv = self.eval_full(e, st, &g.r)?;
                let goal = Rc::new(Value::Eq { ty: rv, lhs: lv, rhs: sv });
                match self.leaf_auto(e, st, goal.clone())? {
                    Some(p) => Ok(p),
                    None => Err(format!("a leaf of the process tree is not closed (goal: {})", e.show(st, &goal).chars().take(600).collect::<String>())),
                }
            }
        }
    }

    /// A back-edge of the fold helper whose lemma is being built: the
    /// residual's leaf is the helper's own call `H ā`, the source's the
    /// recursion's `f ā …`, and the lemma's induction hypothesis `rec(ā;
    /// d)` proves `Eq(R, H ā, E ā)` (the entry `E ā` is `f ā …` by
    /// definition), with `d` the measure's decrease, proven here.
    fn fold_back(&mut self, e: &mut Engine<'_>, st: &St, g: &Goal) -> W<Tm> {
        let own = self.own_fold.clone().ok_or("a fold step outside a fold helper's lemma")?;
        let l = self.real_l(st, &g.l);
        let Some((_, args)) = head_app(&l) else { return Err("a back-edge whose residual is not the helper's call".into()) };
        if args.len() != own.arity as usize {
            return Err("a back-edge with an unexpected argument count".into());
        }
        // the measure at the arguments and at the parameters (the lemma's
        // telescope is the outermost `arity` binders of the context)
        let d = st.depth();
        let arg_tms: Vec<Tm> = args.iter().map(|(_, a)| a.clone()).collect();
        let m_args = subst_n(&own.measure, &arg_tms);
        let m_params = shift(&own.measure, (d - own.arity) as i64);
        e.settle();
        let w = match &*e.env.infer(&st.ctx, &m_args, e.b).map_err(|err| format!("the measure: {err}"))? {
            Value::IntTy(w) => *w,
            _ => return Err("a fold measure that is not a machine integer".into()),
        };
        let goal_tm = mk::eq_bool(e.n.bool_ind, Rc::new(Term::Prim { op: sandblaster_kernel::term::PrimOp::Lt(w), args: vec![m_args.clone(), m_params.clone()], proofs: vec![] }), true);
        let goal = self.eval_full(e, st, &goal_tm)?;
        e.settle();
        let dec = match e.solve(st, goal, true) {
            Ok(Some(p)) => p,
            // a simulated fault's claim (R10): the kernel judges it
            _ if self.trust => Rc::new(Term::Linarith { hyps: vec![], goal: goal_tm, cert: vec![] }),
            _ => return Err("the fold helper's measure does not decrease at a back-edge (not proven)".into()),
        };
        self.stats.leaves_refl += 1;
        Ok(Rc::new(Term::Rec { args: arg_tms, proof: Some(dec) }))
    }

    /// A leaf whose residual calls specialization helpers inside its value
    /// (polyvariant call-site specializations, design §6.5): each helper
    /// call `h dyn̄` is rewritten to its application `def(statics, dyn̄)`
    /// through the helper's lemma (a transport whose motive abstracts the
    /// call in the goal, built by the kernel's `abstract_occurrences`), and
    /// the rewritten residual is the source by conversion. `None`: no
    /// helper call, or the rewritten sides do not convert.
    fn leaf_helpers(&mut self, e: &mut Engine<'_>, st: &St, g: &Goal, lv: &V, sv: &V) -> W<Option<Tm>> {
        use sandblaster_kernel::value::{Head, Neutral};
        if self.specs.is_empty() {
            return Ok(None);
        }
        let by_helper: HashMap<GlobalId, super::SpecLemma> = self.specs.values().map(|i| (i.helper, *i)).collect();
        // the helper applications in the residual's value (distinct)
        let mut apps: Vec<V> = Vec::new();
        let mut seen: HashSet<*const Value> = HashSet::new();
        let mut stack = vec![lv.clone()];
        while let Some(x) = stack.pop() {
            if !seen.insert(Rc::as_ptr(&x)) || seen.len() > 100_000 {
                continue;
            }
            match &*x {
                Value::Ctor { args, .. } => stack.extend(args.iter().filter_map(|a| match a {
                    Arg::Rel(v) => Some(v.clone()),
                    Arg::Irr(_) => None,
                })),
                Value::Pair { fst, snd } => {
                    stack.push(fst.clone());
                    if let Arg::Rel(v) = snd {
                        stack.push(v.clone());
                    }
                }
                Value::Neu(Neutral { head, spine }) => {
                    match head {
                        Head::Global { def, args } => {
                            if by_helper.contains_key(def) && spine.is_empty() {
                                if !apps.iter().any(|a| Rc::ptr_eq(a, &x)) {
                                    apps.push(x.clone());
                                }
                                continue;
                            }
                            stack.extend(args.iter().filter_map(|a| match a {
                                Arg::Rel(v) => Some(v.clone()),
                                Arg::Irr(_) => None,
                            }));
                        }
                        Head::Prim { args, .. } => stack.extend(args.iter().cloned()),
                        _ => {}
                    }
                    for el in spine {
                        if let sandblaster_kernel::value::Elim::App(Arg::Rel(v)) = el {
                            stack.push(v.clone());
                        }
                    }
                }
                _ => {}
            }
        }
        if apps.is_empty() {
            return Ok(None);
        }
        let d = st.depth();
        let rv = self.eval_full(e, st, &g.r)?;
        let mut goal: V = Rc::new(Value::Eq { ty: rv, lhs: lv.clone(), rhs: sv.clone() });
        let mut layers: Vec<(Tm, Tm, Tm, Tm, Tm)> = Vec::new();
        for t_v in apps {
            let Value::Neu(Neutral { head: Head::Global { def: h, .. }, .. }) = &*t_v else { continue };
            let info = by_helper[h];
            e.settle();
            let t_tm = e.quote(st, &t_v);
            let Some((_, args)) = head_app(&t_tm) else { return Ok(None) };
            let inst = mk::apps(mk::global(info.lemma), args.into_iter().filter(|(rel, _)| *rel == Rel::Rel));
            let Ok(e_ty) = e.env.infer(&st.ctx, &inst, e.b) else { return Ok(None) };
            let Some((a_v, _, u_v)) = crate::auto::util::as_eq(&e_ty).map(|(a, l, r)| (a.clone(), l.clone(), r.clone())) else { return Ok(None) };
            let a_tm = e.quote(st, &a_v);
            let u_tm = e.quote(st, &u_v);
            let Ok(motive) = e.env.abstract_occurrences(&st.ctx, &goal, &t_v, e.b) else { return Ok(None) };
            let mut ve = (*st.venv.0).clone();
            ve.push(EnvEntry::Rel(u_v.clone()));
            let Ok(next) = e.env.eval(&VEnv(Rc::new(ve)), Lvl(d + 1), &motive, e.b) else { return Ok(None) };
            let sym = sym_tm(&a_tm, &t_tm, &u_tm, &inst);
            layers.push((a_tm, u_tm, t_tm, sym, motive));
            goal = next;
        }
        let Value::Eq { lhs, rhs, .. } = &*goal else { return Ok(None) };
        e.settle();
        if !e.env.conv(Lvl(d), lhs, rhs, e.b).unwrap_or(false) {
            return Ok(None);
        }
        let mut p = mk::refl(g.r.clone(), g.s.clone());
        for (a_tm, u_tm, t_tm, sym, motive) in layers.into_iter().rev() {
            p = Rc::new(Term::Transport { ty: a_tm, lhs: u_tm, rhs: t_tm, eq: sym, motive, val: p });
        }
        Ok(Some(p))
    }

    /// `auto` on a leaf goal, within [`Walk::leaf_steps`] steps of the
    /// proof's budget (a nested meter scope: running out fails this leaf,
    /// not the whole proof's accounting). `Ok(None)`: not closed.
    fn leaf_auto(&mut self, e: &mut Engine<'_>, st: &St, goal: V) -> W<Option<Tm>> {
        e.settle();
        let before = e.b.steps;
        if before == 0 {
            return Err(format!("the proof's budget is exhausted ({})", crate::auto::meter::failure_note()));
        }
        let cap = before.min(self.leaf_steps);
        e.b.steps = cap;
        let (r, why) = {
            let _scope = crate::auto::meter::Scope::enter(None, e.b);
            let r = e.solve(st, goal, false);
            crate::auto::meter::settle(e.b);
            (r, crate::auto::meter::exhausted())
        };
        let used = cap - e.b.steps.min(cap);
        e.b.steps = before - used;
        e.settle();
        match (r, why) {
            (Ok(Some(p)), None) => Ok(Some(p)),
            (_, Some(x)) => Err(format!("a leaf of the process tree is not closed within its budget ({} steps: {})", self.leaf_steps, crate::auto::meter::describe(x))),
            (Ok(None), None) => Ok(None),
            (Err(_), None) => Err(format!("a leaf of the process tree is not closed within its budget ({} steps)", self.leaf_steps)),
        }
    }

    /// A callee's residual inlined as a value (the tree's `Bind`, a join
    /// point): the residual's `let name = E` is in the context (pushed by
    /// [`Walk::node`]); `P : Eq(A, E, g ā)` comes from the value subtree
    /// (the callee's link, then its residual's body, closed by conversion),
    /// the source's scrutinee `g ā` is rewritten to the `let` variable
    /// (definitionally `E`), and the continuation follows `body`.
    #[allow(clippy::too_many_arguments)]
    fn bind(&mut self, e: &mut Engine<'_>, st: &St, g: Goal, lvl: u32, name: &sandblaster_kernel::term::Name, value: &Node, body: &Node) -> W<Tm> {
        let d = st.depth();
        // the `let` of the join variable: named as the residual named it, or
        // `j` when the elaborator bound the branching value as a join
        // (`let j = match ..`, elab/exec.rs) and the variable as its alias
        let is_let = |l: u32, n: &str| {
            let en = &st.ctx.entries[l as usize];
            en.rel == Rel::Rel && en.def.is_some() && en.name.as_ref() == n
        };
        // the continuation splits on the variable first: the `let` whose
        // variable the residual's head match scrutinizes (possibly through
        // an alias `let`), else by name
        let g = Goal { l: self.real_l(st, &g.l), ..g };
        let by_scrut = HeadMatch::of(&g.l).and_then(|m| match &*m.scrut {
            Term::Var(Idx(i)) => d.checked_sub(1 + i),
            _ => None,
        });
        let resolve = |mut l: u32| -> u32 {
            // an alias `let v = w` stands for `w`
            for _ in 0..8 {
                match self.let_terms.get(&l).map(|t| &**t) {
                    Some(Term::Var(Idx(i))) if l.checked_sub(1 + i).is_some() => l = l - 1 - i,
                    _ => break,
                }
            }
            l
        };
        let pl = by_scrut.map(resolve).filter(|l| st.ctx.entries[*l as usize].def.is_some()).or_else(|| (0..d).rev().find(|l| is_let(*l, name.as_ref()))).or_else(|| (0..d).rev().find(|l| is_let(*l, "j")));
        let Some(pl) = pl else { return Err(format!("the residual has no `let {name}` where the process tree inlines a call")) };
        self.lvl.insert(lvl, pl);
        let e_tm = shift(self.let_terms.get(&pl).ok_or("an inlined value without its term")?, (d - pl) as i64);
        let Some(hm) = HeadMatch::of(&g.s) else { return Err("an inlined call whose result is not matched in the source".into()) };
        let app = hm.scrut.clone();
        let a_tm = e.quote(st, &st.ctx.entries[pl as usize].ty.clone());
        let pv = self.node(e, st, Goal { r: a_tm.clone(), l: e_tm.clone(), s: app.clone() }, value)?;
        // Eq(A, g ā, E), and the `let` variable is `E` by δ
        let p = sym_tm(&a_tm, &e_tm, &app, &pv);
        let (s2, w) = rewrite_head(st, &g, Some(&hm), a_tm, app, st.var(pl), p);
        let pb = self.node(e, st, Goal { r: g.r.clone(), l: g.l.clone(), s: s2 }, body)?;
        Ok(w.apply(pb))
    }

    /// A Σ3 demand split (`Step::Demand`): the residual splits on its own
    /// test, the source not at all — each arm proves the arm's residual
    /// against the unchanged source, with the path equation as a fact.
    fn demand_split(&mut self, e: &mut Engine<'_>, st: &St, g: Goal, ind: IndId, arms: &[crate::opt::drive::tree::Arm]) -> W<Tm> {
        let g = Goal { l: self.real_l(st, &g.l), ..g };
        let Some(lm) = HeadMatch::of(&g.l) else { return Err("the residual has no match where the process tree splits on demand".into()) };
        if lm.ind != ind {
            return Err("the residual's demand split is not on the split's type".into());
        }
        let c_tm = lm.scrut.clone();
        let p_tms = lm.params.clone();
        let mut p_vals = Vec::new();
        for p in &p_tms {
            p_vals.push(self.eval_full(e, st, p)?);
        }
        let a_tm = mk::ind(ind, p_tms.clone());
        let mb = mk::eq(csh(&g.r, 2), lm.rebuild(2, mk::var(1), Some(mk::var(0))), csh(&g.s, 2));
        let motive = mk::pi("e", Rel::Irr, mk::eq(shift(&a_tm, 1), shift(&c_tm, 1), mk::var(0)), mb.clone());
        let out = self.split_arms(e, st, &mb, ind, &c_tm, &p_tms, &p_vals, arms, true)?;
        let m = Rc::new(Term::Match { ind, params: p_tms, scrut: c_tm.clone(), motive, arms: out });
        Ok(mk::app_irr(m, mk::refl(a_tm, c_tm)))
    }

    /// A split merged into one value (design §6.3 Merge, equal arms): the
    /// residual has no match here, so only the source is split — on the
    /// scrutinee the driver split on (the source head's innermost
    /// scrutinee, exposed through `let`s), abstracted in the goal — and
    /// each arm's subtree justifies the same residual value.
    fn split_source(&mut self, e: &mut Engine<'_>, st: &St, g: Goal, ind: IndId, arms: &[crate::opt::drive::tree::Arm]) -> W<Tm> {
        let mut s2 = g.s.clone();
        for _ in 0..4 {
            match self.expose(&s2, st.depth()) {
                Some(t) => s2 = t,
                None => break,
            }
        }
        let Some(mut hm) = HeadMatch::of(&s2) else { return Err("the source has no match where the process tree merges a split".into()) };
        while let Some(im) = HeadMatch::of(&hm.scrut) {
            hm = im;
        }
        if hm.ind != ind {
            return Err("a merged split on a scrutinee of another type".into());
        }
        let c_tm = hm.scrut.clone();
        let p_tms = hm.params.clone();
        let c_full = self.eval_full(e, st, &c_tm)?;
        let mut p_vals = Vec::new();
        for p in &p_tms {
            p_vals.push(self.eval_full(e, st, p)?);
        }
        let a_tm = mk::ind(ind, p_tms.clone());
        let Some((s_body, _, blind)) = super::steps::abstract_source(e, st, &g.r, &s2, &c_tm, &a_tm, &c_full, &self.fact_terms) else { return Err("the merged split's scrutinee does not occur in the source".into()) };
        let mb = mk::eq(csh(&g.r, 2), csh(&g.l, 2), s_body);
        let motive = mk::pi("e", Rel::Irr, mk::eq(shift(&a_tm, 1), shift(&c_tm, 1), mk::var(0)), mb.clone());
        let a_v: V = Rc::new(Value::Ind { ind, params: p_vals.clone() });
        super::steps::check_motive(e, st, &a_v, motive.clone(), blind)?;
        let out = self.split_arms(e, st, &mb, ind, &c_tm, &p_tms, &p_vals, arms, false)?;
        let m = Rc::new(Term::Match { ind, params: p_tms, scrut: c_tm.clone(), motive, arms: out });
        Ok(mk::app_irr(m, mk::refl(a_tm, c_tm)))
    }

    /// The arms of a proof split on `c_tm : ind(p_tms)` with motive body
    /// `mb` (at depth `d + 2`): each binds the constructor's fields and
    /// the path equation (the driver's binders) and follows its subtree;
    /// `reduce_l`: head-reduce the residual side (it has the match too).
    #[allow(clippy::too_many_arguments)]
    fn split_arms(&mut self, e: &mut Engine<'_>, st: &St, mb: &Tm, ind: IndId, c_tm: &Tm, p_tms: &[Tm], p_vals: &[V], arms: &[crate::opt::drive::tree::Arm], reduce_l: bool) -> W<Vec<Arm>> {
        let a_tm = mk::ind(ind, p_tms.to_vec());
        let decl = e.env.inductive_decl(ind).ok_or("unknown inductive")?;
        let mut out = Vec::new();
        for (k, c) in decl.ctors.iter().enumerate() {
            let tarm = arms.iter().find(|a| a.ctor == k as u32).ok_or("the tree has no arm for a constructor")?;
            let mut arm = st.clone();
            let mut fenv: Vec<EnvEntry> = p_vals.iter().map(|x| EnvEntry::Rel(x.clone())).collect();
            for (j, (fname, frel, fty)) in c.fields.iter().enumerate() {
                let lvl = arm.depth();
                e.settle();
                let ftv = e.env.eval(&VEnv(Rc::new(fenv.clone())), Lvl(lvl), fty, e.b).map_err(|err| format!("{err:?}"))?;
                let en = arm.push_raw(e.env, fname.clone(), *frel, ftv);
                if let Some(f) = tarm.fields.get(j) {
                    self.lvl.insert(f.lvl, lvl);
                }
                fenv.push(en);
            }
            let nf = c.fields.len() as u32;
            let fields_here: Vec<Tm> = (0..nf).map(|j| mk::var(nf - 1 - j)).collect();
            let ctor_here = mk::ctor(ind, k as u32, p_tms.iter().map(|p| shift(p, nf as i64)).collect(), fields_here);
            let e_dom = mk::eq(shift(&a_tm, nf as i64), shift(c_tm, nf as i64), ctor_here.clone());
            let e_lvl = arm.depth();
            let eq_ty = self.eval_full(e, &arm, &e_dom)?;
            let eq_small = self.eval(e, &arm, &e_dom)?;
            self.fact_terms.insert(e_lvl, e_dom.clone());
            arm.push_raw(e.env, Rc::from("e"), Rel::Irr, eq_ty);
            arm.add_ctx_fact(e_lvl, eq_small, crate::auto::state::Origin::Split);
            self.lvl.insert(tarm.eq_lvl, e_lvl);
            let ctor_tm = shift(&ctor_here, 1);
            let arm_goal = super::steps::inst2(mb, &ctor_tm, &mk::var(0), nf + 1);
            let Term::Eq { ty: rk, lhs: lk, rhs: sk } = &*arm_goal else { return Err("an arm goal that is not an equation".into()) };
            let lk = if reduce_l { head_reduce(lk) } else { lk.clone() };
            let pk = self.node(e, &arm, Goal { r: rk.clone(), l: lk, s: sk.clone() }, &tarm.body)?;
            out.push(Arm { names: c.fields.iter().map(|f| f.0.clone()).collect(), body: mk::lam("e", Rel::Irr, e_dom, pk) });
        }
        Ok(out)
    }

    /// The dependent-match idiom on the two head matches (see the module
    /// docs).
    fn split(&mut self, e: &mut Engine<'_>, st: &St, g: Goal, ind: IndId, arms: &[crate::opt::drive::tree::Arm]) -> W<Tm> {
        let g = Goal { l: self.real_l(st, &g.l), ..g };
        let Some(lm) = HeadMatch::of(&g.l) else { return Err("the residual has no match where the process tree splits".into()) };
        let Some(sm) = HeadMatch::of(&g.s) else { return Err("the source has no match where the process tree splits".into()) };
        if lm.ind != ind {
            return Err("the residual's match is not on the split's type".into());
        }
        let c_tm = lm.scrut.clone();
        let p_tms = lm.params.clone();
        let c_full = self.eval_full(e, st, &c_tm)?;
        let sc_full = self.eval_full(e, st, &sm.scrut)?;
        e.settle();
        // (a source match on another type: the split is on a scrutinee
        // nested in the source's head scrutinee — case-of-case, design
        // §6.4 — abstracted below)
        let direct = sm.ind == ind && e.env.conv(Lvl(st.depth()), &c_full, &sc_full, e.b).unwrap_or(false);
        let mut p_vals = Vec::new();
        for p in &p_tms {
            p_vals.push(self.eval_full(e, st, p)?);
        }
        let a_tm = mk::ind(ind, p_tms.clone());
        // the motive's body `y, e ⊢ Eq(R, L[y, e], S[y, e])`
        // proofs the abstraction kept without a readable type (none when
        // the two scrutinees are replaced directly: no motive check)
        let mut blind = 0;
        let mb = if direct {
            // both head matches on convertible scrutinees: replace the two
            // scrutinees (and idiom arguments)
            // (the source's idiom may name an earlier scrutinee `s₀` than
            // its current one: its argument `q : Eq(A, s₀, c)` is extended
            // by the motive's equation, `trans(q, e) : Eq(A, s₀, y)`)
            let s_arg = match (&sm.idiom, idiom_scrut(&sm)) {
                (Some(q), Some(s0)) if !e.env.alpha_eq_relevant(&s0, &sm.scrut, &|x, y| x == y) => {
                    let a2 = shift(&mk::ind(ind, sm.params.clone()), 2);
                    trans_tm(&a2, &shift(&s0, 2), &shift(&sm.scrut, 2), &mk::var(1), &shift(q, 2), &mk::var(0))
                }
                _ => mk::var(0),
            };
            mk::eq(csh(&g.r, 2), lm.rebuild(2, mk::var(1), Some(mk::var(0))), sm.rebuild(2, mk::var(1), Some(s_arg)))
        } else {
            // the source splits on a scrutinee nested in its head's
            // scrutinee (a `let`-bound condition such as `a && b`): expose
            // it, then abstract it semantically (a commuting conversion:
            // the inner match reduces in each arm, then the outer one)
            let mut s2 = g.s.clone();
            for _ in 0..4 {
                match self.expose(&s2, st.depth()) {
                    Some(t) => s2 = t,
                    None => break,
                }
            }
            // the residual splits on its head match (replaced directly), the
            // source's occurrences are abstracted
            match super::steps::abstract_source(e, st, &g.r, &s2, &c_tm, &a_tm, &c_full, &self.fact_terms) {
                Some((s_body, _, b)) => {
                    blind = b;
                    mk::eq(csh(&g.r, 2), lm.rebuild(2, mk::var(1), Some(mk::var(0))), s_body)
                }
                None => return Err("the residual and the source split on different scrutinees".into()),
            }
        };
        if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
            let mut names = st.names();
            let cut = |s: String| s.chars().take(1500).collect::<String>();
            eprintln!("opt: proof: split (direct {direct}) on {}", cut(e.env.print_term(&names, &c_tm)));
            names.push(std::rc::Rc::from("Y"));
            names.push(std::rc::Rc::from("E"));
            if let Term::Eq { rhs, .. } = &*mb
                && let Some(hm) = HeadMatch::of(rhs)
            {
                let mut sc = hm.scrut.clone();
                while let Some(im) = HeadMatch::of(&sc) {
                    sc = im.scrut.clone();
                }
                eprintln!("opt: proof: split: source scrutinee after abstraction {}", cut(e.env.print_term(&names, &sc)));
            }
            if let Some(hm) = HeadMatch::of(&g.s) {
                let mut sc = hm.scrut.clone();
                while let Some(im) = HeadMatch::of(&sc) {
                    sc = im.scrut.clone();
                }
                names.pop();
                names.pop();
                eprintln!("opt: proof: split: source scrutinee before {}", cut(e.env.print_term(&names, &sc)));
            }
        }
        let motive = mk::pi("e", Rel::Irr, mk::eq(shift(&a_tm, 1), shift(&c_tm, 1), mk::var(0)), mb.clone());
        if !direct {
            // a motive built by abstraction is checked before use
            let a_v: V = Rc::new(Value::Ind { ind, params: p_vals.clone() });
            super::steps::check_motive(e, st, &a_v, motive.clone(), blind)?;
        }
        let decl = e.env.inductive_decl(ind).ok_or("unknown inductive")?;
        let mut out = Vec::new();
        for (k, c) in decl.ctors.iter().enumerate() {
            let tarm = arms.iter().find(|a| a.ctor == k as u32).ok_or("the tree has no arm for a constructor")?;
            let mut arm = st.clone();
            let mut fenv: Vec<EnvEntry> = p_vals.iter().map(|x| EnvEntry::Rel(x.clone())).collect();
            for (j, (fname, frel, fty)) in c.fields.iter().enumerate() {
                let lvl = arm.depth();
                e.settle();
                let ftv = e.env.eval(&VEnv(Rc::new(fenv.clone())), Lvl(lvl), fty, e.b).map_err(|err| format!("{err:?}"))?;
                let en = arm.push_raw(e.env, fname.clone(), *frel, ftv);
                if let Some(f) = tarm.fields.get(j) {
                    self.lvl.insert(f.lvl, lvl);
                }
                fenv.push(en);
            }
            let nf = c.fields.len() as u32;
            let fields_here: Vec<Tm> = (0..nf).map(|j| mk::var(nf - 1 - j)).collect();
            let ctor_here = mk::ctor(ind, k as u32, p_tms.iter().map(|p| shift(p, nf as i64)).collect(), fields_here);
            let e_dom = mk::eq(shift(&a_tm, nf as i64), shift(&c_tm, nf as i64), ctor_here.clone());
            let e_lvl = arm.depth();
            // the binder's type in the definitional view (the kernel's), the
            // fact's stated type in the evaluation view (small atoms)
            let eq_ty = self.eval_full(e, &arm, &e_dom)?;
            let eq_small = self.eval(e, &arm, &e_dom)?;
            self.fact_terms.insert(e_lvl, e_dom.clone());
            arm.push_raw(e.env, Rc::from("e"), Rel::Irr, eq_ty);
            arm.add_ctx_fact(e_lvl, eq_small, crate::auto::state::Origin::Split);
            self.lvl.insert(tarm.eq_lvl, e_lvl);
            // the arm's goal: the motive's body at y := Cₖ(fields), e := e
            let ctor_tm = shift(&ctor_here, 1);
            let arm_goal = super::steps::inst2(&mb, &ctor_tm, &mk::var(0), nf + 1);
            let Term::Eq { ty: rk, lhs: lk, rhs: sk } = &*arm_goal else { return Err("an arm goal that is not an equation".into()) };
            let pk = self.node(e, &arm, Goal { r: rk.clone(), l: head_reduce(lk), s: sk.clone() }, &tarm.body)?;
            out.push(Arm { names: c.fields.iter().map(|f| f.0.clone()).collect(), body: mk::lam("e", Rel::Irr, e_dom, pk) });
        }
        let m = Rc::new(Term::Match { ind, params: p_tms, scrut: c_tm.clone(), motive, arms: out });
        Ok(mk::app_irr(m, mk::refl(a_tm, c_tm)))
    }
}

/// The goal with a new source side.
fn with_source(g: &Goal, (s, w): (Tm, Wrap)) -> (Goal, Wrap) {
    (Goal { r: g.r.clone(), l: g.l.clone(), s }, w)
}

/// Rewrites `app` (the whole source, or its head match's scrutinee) to
/// `to` with `p : Eq(A, app, to)`: the new source and the wrap.
fn rewrite_head(st: &St, g: &Goal, hm: Option<&HeadMatch>, a_tm: Tm, app: Tm, to: Tm, p: Tm) -> (Tm, Wrap) {
    let eq = sym_tm(&a_tm, &app, &to, &p);
    match hm {
        None => {
            // z. Eq(R, L, z)
            let motive = mk::eq(csh(&g.r, 1), csh(&g.l, 1), mk::var(0));
            (to.clone(), Wrap { depth: st.depth(), ty: a_tm, lhs: to, rhs: app, eq, motive, e_dom: None })
        }
        Some(hm) if hm.idiom.is_some() => {
            // z. Π(e :Irr Eq(A, app, z)). Eq(R, L, (match z ..) trans(q, e)):
            // the match's motive expects an equation from the scrutinee its
            // motive names (`s₀`, which an earlier rewrite may have left
            // behind), and its argument `q : Eq(A, s₀, app)` is extended by
            // the new step; the new source: the match on `to` with
            // `trans(q, p)`
            let q = hm.idiom.clone().unwrap();
            let s0 = idiom_scrut(hm).unwrap_or_else(|| app.clone());
            let arg_z = trans_tm(&shift(&a_tm, 2), &shift(&s0, 2), &shift(&app, 2), &mk::var(1), &shift(&q, 2), &mk::var(0));
            let body = mk::eq(csh(&g.r, 2), csh(&g.l, 2), hm.rebuild(2, mk::var(1), Some(arg_z)));
            let motive = mk::pi("e", Rel::Irr, mk::eq(shift(&a_tm, 1), shift(&app, 1), mk::var(0)), body);
            let e_dom = mk::eq(a_tm.clone(), app.clone(), to.clone());
            let arg = trans_tm(&a_tm, &s0, &app, &to, &q, &p);
            (hm.rebuild(0, to.clone(), Some(arg)), Wrap { depth: st.depth(), ty: a_tm, lhs: to, rhs: app, eq, motive, e_dom: Some(e_dom) })
        }
        Some(hm) => {
            // z. Eq(R, L, match z ..)
            let motive = mk::eq(csh(&g.r, 1), csh(&g.l, 1), hm.rebuild(1, mk::var(0), None));
            (hm.rebuild(0, to.clone(), None), Wrap { depth: st.depth(), ty: a_tm, lhs: to, rhs: app, eq, motive, e_dom: None })
        }
    }
}
