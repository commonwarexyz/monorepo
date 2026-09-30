//! Script statements with an elaboration of their own (DESIGN.md §4.4,
//! docs/PROOF-GUIDE.md). Mounted by [`super`] (`elab::script`).
//!
//! * `apply(lemma)` — [`Elab::apply_infer`]: the lemma's arguments are
//!   inferred by **first-order matching** of its `requires` against the facts
//!   in scope and of its `ensures` against the goal, on terms (facts keep
//!   their type *terms*, [`super::super::Scope::fact_tys`], so calls stay
//!   folded). A pattern and a term whose heads differ are unfolded towards
//!   each other (transparent, non-recursive definitions only,
//!   [`super::super::tm::head_unfold`]); proofs (irrelevant positions) are
//!   ignored. The chosen instantiation is the one that uses the most facts
//!   (the goal counts as one); two different ones are an ambiguity. The
//!   application is then built exactly like an explicit call: every
//!   `requires` is proven by the prover and the kernel checks the result, so
//!   the matcher is untrusted.
//! * `by_computation()` — [`Elab::by_computation`]: the goal is an equation
//!   (or a `bool`) whose sides convert; no proof search. On failure the
//!   diagnostic shows both evaluated sides.
//! * `calc! { .. }` — [`Elab::calc_chain`]: every link is proven (its `by`
//!   steps, or the prover); `==` chains are combined by transport
//!   (transitivity), chains with `<=`/`<` by the prover (linear arithmetic)
//!   over the links as facts.

use std::rc::Rc;

use sandblaster_kernel::term::{Idx, Lvl, Name, Rel, Term, Tm};
use sandblaster_kernel::util::{mk, occurs, shift};
use sandblaster_kernel::value::Value;

use super::super::{internal, Elab, ElabError, ErrKind, Mode, Val, R};
use crate::diag::{DiagKind, Diagnostic};
use crate::hir::*;
use crate::prover::{AutoFailure, FactOrigin, ObligationKind};
use crate::span::Span;

/// The role of a binder of a lemma's kernel telescope.
#[derive(Clone, Copy, PartialEq, Debug)]
enum B {
    /// Instantiated by matching (a lemma parameter, or a type parameter
    /// fixed by the call's type arguments).
    Meta,
    /// A hypothesis: proven at the application.
    Hyp,
}

/// Matching work limit (term nodes visited, unfoldings) per `apply`.
const FUEL: u32 = 200_000;
/// At most this many search nodes when combining per-hypothesis matches.
const SEARCH: u32 = 20_000;

/// A (partial) instantiation: one term (at the context depth) per binder.
type Subst = Vec<Option<Tm>>;

/// `(relevance, argument)` spine of an application.
fn spine(t: &Tm) -> (Tm, Vec<(Rel, Tm)>) {
    let mut args = Vec::new();
    let mut h = t.clone();
    while let Term::App { fun, arg, rel } = &*h.clone() {
        args.push((*rel, arg.clone()));
        h = fun.clone();
    }
    args.reverse();
    (h, args)
}

/// Whether `t` has the head shape of `other`: the same global applied to
/// as many arguments, or the same node kind (non-applications).
fn same_shape(t: &Term, other: &Tm) -> bool {
    let t = Rc::new(clone_shallow(t));
    let (ht, at) = spine(&t);
    let (ho, ao) = spine(other);
    match (&*ht, &*ho) {
        (Term::Global(a), Term::Global(b)) => a == b && at.len() == ao.len(),
        (Term::Global(_), _) | (_, Term::Global(_)) => false,
        // e.g. a dependent `match` applied to `refl` (`a && b`)
        _ => at.len() == ao.len() && std::mem::discriminant(&*ht) == std::mem::discriminant(&*ho),
    }
}

/// A shallow copy of a term node (children shared).
fn clone_shallow(t: &Term) -> Term {
    match t {
        Term::Var(i) => Term::Var(*i),
        Term::Global(g) => Term::Global(*g),
        Term::App { rel, fun, arg } => Term::App { rel: *rel, fun: fun.clone(), arg: arg.clone() },
        Term::Match { ind, params, scrut, motive, arms } => Term::Match {
            ind: *ind,
            params: params.clone(),
            scrut: scrut.clone(),
            motive: motive.clone(),
            arms: arms.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: a.body.clone() }).collect(),
        },
        Term::Eq { ty, lhs, rhs } => Term::Eq { ty: ty.clone(), lhs: lhs.clone(), rhs: rhs.clone() },
        Term::Ctor { ind, ctor, params, args } => Term::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args: args.clone() },
        Term::Prim { op, args, proofs } => Term::Prim { op: *op, args: args.clone(), proofs: proofs.clone() },
        Term::Let { name, rel, ty, val, body } => Term::Let { name: name.clone(), rel: *rel, ty: ty.clone(), val: val.clone(), body: body.clone() },
        Term::Lit { w, n } => Term::Lit { w: *w, n: n.clone() },
        Term::Ind { ind, params } => Term::Ind { ind: *ind, params: params.clone() },
        Term::Fst(x) => Term::Fst(x.clone()),
        Term::Snd(x) => Term::Snd(x.clone()),
        Term::Sigma { name, snd_rel, fst, snd } => Term::Sigma { name: name.clone(), snd_rel: *snd_rel, fst: fst.clone(), snd: snd.clone() },
        Term::Pi { name, rel, dom, cod } => Term::Pi { name: name.clone(), rel: *rel, dom: dom.clone(), cod: cod.clone() },
        Term::Lam { name, rel, dom, body } => Term::Lam { name: name.clone(), rel: *rel, dom: dom.clone(), body: body.clone() },
        Term::Pair { ty, fst, snd } => Term::Pair { ty: ty.clone(), fst: fst.clone(), snd: snd.clone() },
        Term::IntTy(w) => Term::IntTy(*w),
        Term::Sort(s) => Term::Sort(*s),
        // other nodes never need a shape test: compare by kind only
        _ => Term::Erased,
    }
}

/// The matcher: patterns are the telescope's binder types (a pattern at
/// telescope depth `pd`, under `b` local binders); terms are fact/goal terms
/// at the context depth `d` (under the same `b` local binders).
struct Matcher<'e, 'a> {
    el: &'e Elab<'a>,
    kinds: &'e [B],
    fuel: u32,
}

impl Matcher<'_, '_> {
    fn same_term(&self, a: &Tm, b: &Tm) -> bool {
        if Rc::ptr_eq(a, b) || self.el.env.alpha_eq_relevant(a, b, &|x, y| x == y) {
            return true;
        }
        let (Ok(va), Ok(vb)) = (self.el.eval(a), self.el.eval(b)) else { return false };
        let mut bud = self.el.budget();
        self.el.env.conv(Lvl(self.el.depth()), &va, &vb, &mut bud).unwrap_or(false)
    }

    fn bind(&self, lvl: usize, f: &Tm, b: u32, s: &mut Subst) -> bool {
        if (0..b).any(|i| occurs(f, i)) {
            // mentions a local binder: no instantiation from here; accepted
            // when only proofs mention it (the right operand of a dependent
            // `&&` may use the left one as a fact) — the binder must then be
            // instantiated elsewhere
            return !(0..b).any(|i| occurs_relevant(f, i));
        }
        let t = if b == 0 { f.clone() } else { shift(f, -(b as i64)) };
        match &s[lvl] {
            None => {
                s[lvl] = Some(t);
                true
            }
            Some(t0) => {
                let t0 = t0.clone();
                self.same_term(&t0, &t)
            }
        }
    }

    fn mt(&mut self, p: &Tm, pd: u32, f: &Tm, b: u32, s: &mut Subst) -> bool {
        if self.fuel == 0 {
            return false;
        }
        self.fuel -= 1;
        if let Term::Var(Idx(i)) = &**p {
            if *i < b {
                return matches!(&**f, Term::Var(Idx(j)) if j == i);
            }
            let Some(lvl) = (pd as i64 - 1 - (*i - b) as i64).try_into().ok().filter(|l: &usize| *l < self.kinds.len()) else { return false };
            return match self.kinds[lvl] {
                // a hypothesis binder only occurs in proofs
                B::Hyp => true,
                B::Meta => self.bind(lvl, f, b, s),
            };
        }
        if matches!(&**p, Term::Erased) || matches!(&**f, Term::Erased) {
            return true;
        }
        let saved = s.clone();
        if let Some(r) = self.mt_same(p, pd, f, b, s) {
            if !r {
                *s = saved;
            }
            return r;
        }
        // shapes differ: unfold the term, then the pattern, towards the other
        if let Some(f2) = self.unfold_toward(f, p, Some(b)) {
            return self.mt(p, pd, &f2, b, s);
        }
        if let Some(p2) = self.unfold_toward(p, f, None) {
            return self.mt(&p2, pd, f, b, s);
        }
        if std::env::var_os("SANDBLASTER_TRACE_APPLY").is_some() {
            let pr = |t: &Tm| sandblaster_kernel::syntax::printer::print_term_bounded(&self.el.env, &[], t, 300);
            eprintln!("apply: mismatch\n  pattern: {}\n  term:    {}", pr(p), pr(f));
        }
        false
    }

    /// One step of head normalization of `t` towards the shape of `other`:
    /// a `let` (of the term, or a let-bound variable of the context), the
    /// redexes of a substitution, a `match` on a scrutinee that evaluates to
    /// a constructor, the unfolding of the head function up to `other`'s
    /// shape, or one unfolding of the head function. `term` is `Some(b)` for
    /// a fact/goal term under `b` local binders (`None`: a pattern; only
    /// lets, redexes and targeted unfolding).
    fn unfold_toward(&mut self, t: &Tm, other: &Tm, term: Option<u32>) -> Option<Tm> {
        if self.fuel < 16 {
            return None;
        }
        self.fuel -= 16;
        let ctx = term == Some(0);
        if let (Term::Var(Idx(i)), Some(b)) = (&**t, term)
            && *i >= b
        {
            let d = self.el.depth();
            let lvl = d.checked_sub(1 + (*i - b))?;
            let e = self.el.f.scope.ctx.entries.get(lvl as usize)?;
            let Some(sandblaster_kernel::value::Arg::Rel(v)) = &e.def else { return None };
            let q = self.el.quote(v, None);
            if super::super::tm::size_capped(&q, 4096) >= 4096 {
                return None;
            }
            return Some(if b == 0 { q } else { shift(&q, b as i64) });
        }
        if let Term::Let { val, body, .. } = &**t {
            return Some(super::super::tm::simp_redexes(&super::super::tm::subst0(body, val)));
        }
        // redexes left by substitution (`match` on a constructor, β)
        let r = super::super::tm::simp_redexes(t);
        if super::super::tm::fingerprint(&r) != super::super::tm::fingerprint(t) {
            return Some(r);
        }
        if ctx && let Some(r) = self.decide_scrutinee(t) {
            return Some(r);
        }
        let (h, _) = spine(t);
        if !matches!(&*h, Term::Global(_)) {
            return None;
        }
        let o = other.clone();
        if let Some(r) = super::super::tm::head_unfold(&self.el.env, t, &|x| same_shape(x, &o)) {
            return (!Rc::ptr_eq(&r, t)).then_some(r);
        }
        term?;
        // one unfolding (the shape shows up after a decided `match`)
        let calls = std::cell::Cell::new(0u32);
        let r = super::super::tm::head_unfold(&self.el.env, t, &|_| {
            calls.set(calls.get() + 1);
            calls.get() > 1
        })?;
        (super::super::tm::fingerprint(&r) != super::super::tm::fingerprint(t)).then_some(r)
    }

    /// A `match` (possibly applied to `refl`, as in `a && b`) whose
    /// scrutinee evaluates to a (small) constructor (`!true`, `exact(Some((x,
    /// [])))`, ..): the selected arm. Only for terms of the context (no local binders).
    fn decide_scrutinee(&mut self, t: &Tm) -> Option<Tm> {
        if self.fuel < 64 {
            return None;
        }
        self.fuel -= 64;
        let (h, args) = spine(t);
        let Term::Match { ind, params, scrut, motive, arms } = &*h else { return None };
        let v = self.el.eval(scrut).ok()?;
        // a constructor (small once quoted: `Some(x)`, `false`, ..)
        let lit = match &*v {
            Value::Ctor { .. } | Value::Lit { .. } => {
                let q = self.el.quote(&v, None);
                if super::super::tm::size_capped(&q, 256) >= 256 {
                    return None;
                }
                q
            }
            _ => return None,
        };
        let arms = arms.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: a.body.clone() }).collect();
        let mut m: Tm = Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: lit, motive: motive.clone(), arms });
        for (rel, a) in args {
            m = Rc::new(Term::App { rel, fun: m, arg: a });
        }
        let r = super::super::tm::simp_redexes(&m);
        (super::super::tm::fingerprint(&r) != super::super::tm::fingerprint(t)).then_some(r)
    }

    fn all(&mut self, ps: &[Tm], pd: u32, fs: &[Tm], b: u32, s: &mut Subst) -> bool {
        ps.len() == fs.len() && ps.iter().zip(fs).all(|(p, f)| self.mt(p, pd, f, b, s))
    }

    /// Structural comparison of nodes of the same shape (`None`: the shapes
    /// differ).
    fn mt_same(&mut self, p: &Tm, pd: u32, f: &Tm, b: u32, s: &mut Subst) -> Option<bool> {
        let (hp, ap) = spine(p);
        let (hf, af) = spine(f);
        if !ap.is_empty() || !af.is_empty() {
            if ap.len() != af.len() {
                return None;
            }
            let heads = match (&*hp, &*hf) {
                // different functions: unfold one of them (the caller)
                (Term::Global(x), Term::Global(y)) if x != y => return None,
                (Term::Global(_), Term::Global(_)) => true,
                (Term::Global(_), _) | (_, Term::Global(_)) => return None,
                (Term::Var(Idx(x)), Term::Var(Idx(y))) if *x < b => x == y,
                (Term::Var(_), _) | (_, Term::Var(_)) => return None,
                // other heads (a dependent `match` applied to `refl`, ..)
                _ if std::mem::discriminant(&*hp) == std::mem::discriminant(&*hf) => self.mt_same(&hp, pd, &hf, b, s)?,
                _ => return None,
            };
            if !heads {
                return Some(false);
            }
            for ((rp, xp), (_, xf)) in ap.iter().zip(&af) {
                if *rp == Rel::Irr {
                    continue;
                }
                if !self.mt(xp, pd, xf, b, s) {
                    return Some(false);
                }
            }
            return Some(true);
        }
        Some(match (&**p, &**f) {
            (Term::Global(x), Term::Global(y)) => x == y,
            (Term::Var(_), _) | (_, Term::Var(_)) => return None,
            (Term::Sort(x), Term::Sort(y)) => x == y,
            (Term::IntTy(x), Term::IntTy(y)) => x == y,
            (Term::Lit { w: w1, n: n1 }, Term::Lit { w: w2, n: n2 }) => w1 == w2 && n1 == n2,
            (Term::Eq { ty: t1, lhs: l1, rhs: r1 }, Term::Eq { ty: t2, lhs: l2, rhs: r2 }) => self.mt(t1, pd, t2, b, s) && self.mt(l1, pd, l2, b, s) && self.mt(r1, pd, r2, b, s),
            (Term::Ind { ind: i1, params: p1 }, Term::Ind { ind: i2, params: p2 }) => i1 == i2 && self.all(p1, pd, p2, b, s),
            (Term::Ctor { ind: i1, ctor: c1, params: p1, args: a1 }, Term::Ctor { ind: i2, ctor: c2, params: p2, args: a2 }) => {
                i1 == i2 && c1 == c2 && self.all(p1, pd, p2, b, s) && self.all(a1, pd, a2, b, s)
            }
            (Term::Match { ind: i1, params: p1, scrut: s1, arms: m1, .. }, Term::Match { ind: i2, params: p2, scrut: s2, arms: m2, .. }) => {
                i1 == i2
                    && m1.len() == m2.len()
                    && self.all(p1, pd, p2, b, s)
                    && self.mt(s1, pd, s2, b, s)
                    && m1.iter().zip(m2).all(|(x, y)| x.names.len() == y.names.len() && self.mt(&x.body, pd, &y.body, b + x.names.len() as u32, s))
            }
            (Term::Prim { op: o1, args: a1, .. }, Term::Prim { op: o2, args: a2, .. }) => o1 == o2 && self.all(a1, pd, a2, b, s),
            (Term::Fst(x), Term::Fst(y)) | (Term::Snd(x), Term::Snd(y)) => self.mt(x, pd, y, b, s),
            (Term::Pair { fst: f1, snd: s1, ty }, Term::Pair { fst: f2, snd: s2, .. }) => {
                let irr_snd = matches!(&**ty, Term::Sigma { snd_rel: Rel::Irr, .. });
                self.mt(f1, pd, f2, b, s) && (irr_snd || self.mt(s1, pd, s2, b, s))
            }
            (Term::Sigma { fst: f1, snd: s1, snd_rel: r1, .. }, Term::Sigma { fst: f2, snd: s2, snd_rel: r2, .. }) => r1 == r2 && self.mt(f1, pd, f2, b, s) && self.mt(s1, pd, s2, b + 1, s),
            (Term::Pi { dom: d1, cod: c1, rel: r1, .. }, Term::Pi { dom: d2, cod: c2, rel: r2, .. }) | (Term::Lam { dom: d1, body: c1, rel: r1, .. }, Term::Lam { dom: d2, body: c2, rel: r2, .. }) => {
                r1 == r2 && self.mt(d1, pd, d2, b, s) && self.mt(c1, pd, c2, b + 1, s)
            }
            (Term::Let { rel: r1, val: v1, body: b1, .. }, Term::Let { rel: r2, val: v2, body: b2, .. }) if r1 == r2 => (*r1 == Rel::Irr || self.mt(v1, pd, v2, b, s)) && self.mt(b1, pd, b2, b + 1, s),
            (Term::Axiom { ax: x1, args: a1 }, Term::Axiom { ax: x2, args: a2 }) => x1 == x2 && self.all(a1, pd, a2, b, s),
            // proofs: irrelevant
            (Term::Refl { .. }, Term::Refl { .. }) | (Term::Linarith { .. }, Term::Linarith { .. }) | (Term::BvRefl { .. }, Term::BvRefl { .. }) | (Term::Absurd { .. }, Term::Absurd { .. }) => true,
            (Term::Transport { val: v1, .. }, Term::Transport { val: v2, .. }) => self.mt(v1, pd, v2, b, s),
            _ => return None,
        })
    }
}

/// Whether `Var(idx)` occurs in `t` outside proofs (irrelevant positions:
/// irrelevant arguments and lets, proofs of primitives, certificates).
fn occurs_relevant(t: &Tm, idx: u32) -> bool {
    fn go(t: &Tm, k: u32, memo: &mut std::collections::HashSet<(*const Term, u32)>) -> bool {
        if !memo.insert((Rc::as_ptr(t), k)) {
            return false;
        }
        match &**t {
            Term::Var(Idx(i)) => *i == k,
            Term::App { rel: Rel::Irr, fun, .. } => go(fun, k, memo),
            Term::App { fun, arg, .. } => go(fun, k, memo) || go(arg, k, memo),
            Term::Prim { args, .. } => args.iter().any(|a| go(a, k, memo)),
            Term::Let { rel, ty, val, body, .. } => (*rel == Rel::Rel && (go(ty, k, memo) || go(val, k, memo))) || go(body, k + 1, memo),
            Term::Refl { .. } | Term::Linarith { .. } | Term::BvRefl { .. } | Term::Erased => false,
            Term::Absurd { ty, .. } => go(ty, k, memo),
            Term::Transport { ty, lhs, rhs, motive, val, .. } => go(ty, k, memo) || go(lhs, k, memo) || go(rhs, k, memo) || go(motive, k + 1, memo) || go(val, k, memo),
            Term::Pi { dom, cod: b, .. } | Term::Lam { dom, body: b, .. } | Term::Sigma { fst: dom, snd: b, .. } => go(dom, k, memo) || go(b, k + 1, memo),
            Term::Match { params, scrut, motive, arms, .. } => {
                params.iter().any(|p| go(p, k, memo)) || go(scrut, k, memo) || go(motive, k + 1, memo) || arms.iter().any(|a| go(&a.body, k + a.names.len() as u32, memo))
            }
            _ => {
                let mut found = false;
                super::super::tm::children_depth(t, &mut |c, d| {
                    if !found {
                        found = go(c, k + d, memo);
                    }
                });
                found
            }
        }
    }
    go(t, idx, &mut std::collections::HashSet::new())
}

/// Merges two instantiations (`None` if they disagree).
fn merge(m: &Matcher, a: &Subst, b: &Subst) -> Option<Subst> {
    let mut out = a.clone();
    for (k, x) in b.iter().enumerate() {
        match (&out[k], x) {
            (_, None) => {}
            (None, Some(t)) => out[k] = Some(t.clone()),
            (Some(t0), Some(t)) => {
                if !m.same_term(t0, t) {
                    return None;
                }
            }
        }
    }
    Some(out)
}

/// The conjuncts of a fact term (`p && q` facts are Σ types whose second
/// component does not depend on the first), for matching; a boolean
/// integer comparison `(x == y) == true` also stands for the proposition
/// `x == y`.
fn conjuncts(t: &Tm, out: &mut Vec<Tm>) {
    out.push(t.clone());
    if let Term::Eq { lhs, rhs, .. } = &**t
        && let Term::Prim { op: sandblaster_kernel::term::PrimOp::Eq(w), args, .. } = &**lhs
        && let Term::Ctor { ctor: 1, args: cargs, .. } = &**rhs
        && cargs.is_empty()
        && args.len() == 2
    {
        out.push(mk::eq(mk::int_ty(*w), args[0].clone(), args[1].clone()));
    }
    if let Term::Sigma { fst, snd, .. } = &**t {
        conjuncts(fst, out);
        if !occurs(snd, 0) {
            conjuncts(&shift(snd, -1), out);
        }
    }
}

impl<'a> Elab<'a> {
    /// `apply(lemma)`: the application of the lemma with arguments inferred
    /// from the facts in scope (and the goal, if any); its proof and
    /// instantiated conclusion (see the module docs).
    pub(super) fn apply_infer(&mut self, app: &'a Expr, goal: Option<&Val>, relevant: bool) -> R<(Tm, Tm)> {
        let ExprKind::Call { callee: Callee::Item(id, targs), .. } = &app.kind else { return internal(app.span, "`apply`: not a call") };
        let (id, span) = (*id, app.span);
        let item = self.krate.item(id);
        let lname = item.name.clone();
        let g = self.item_global(id, span)?;
        let lty = self.env.global_type(g).ok_or_else(|| ElabError { span, msg: "lemma without type".into(), kind: ErrKind::Internal })?;
        // binder roles
        let (kinds, fixed): (Vec<B>, Vec<Option<usize>>) = if crate::resolve::prelude_lemma_kernel_name(&item.path).is_some() {
            let sig = crate::auto::surface::sig(&self.env, g).ok_or_else(|| ElabError { span, msg: "prelude lemma without a surface signature".into(), kind: ErrKind::Internal })?;
            sig.roles
                .iter()
                .map(|r| match r {
                    crate::auto::surface::Role::Type(i) => (B::Meta, Some(*i)),
                    crate::auto::surface::Role::Value { .. } => (B::Meta, None),
                    crate::auto::surface::Role::Hyp => (B::Hyp, None),
                })
                .unzip()
        } else {
            let f = self.krate.fn_def(id).ok_or_else(|| ElabError { span, msg: "lemma is not a function".into(), kind: ErrKind::Internal })?;
            let (ng, np, nr) = (f.generics.len(), f.params.len(), f.requires.len());
            // the parameters' `Nat` bounds (`h_nat…`, `Elab::fn_params`) sit
            // between the parameters and the `requires`: hypotheses too
            let mut t = lty.clone();
            let mut nn = 0usize;
            for k in 0.. {
                let Term::Pi { name, cod, .. } = &*t.clone() else { break };
                if k >= ng + np {
                    if !name.starts_with("h_nat") {
                        break;
                    }
                    nn += 1;
                }
                t = cod.clone();
            }
            (0..ng + np + nn + nr).map(|k| if k < ng { (B::Meta, Some(k)) } else if k < ng + np { (B::Meta, None) } else { (B::Hyp, None) }).unzip()
        };
        // the telescope: binder types (patterns) and the conclusion
        let mut doms: Vec<(Rel, Tm, Name)> = Vec::new();
        let mut t = lty.clone();
        for _ in 0..kinds.len() {
            let Term::Pi { rel, dom, cod, name } = &*t.clone() else { return internal(span, "`apply`: lemma telescope") };
            doms.push((*rel, dom.clone(), name.clone()));
            t = cod.clone();
        }
        let concl_pat = t;
        let n = kinds.len();
        let d = self.depth();
        // type arguments are fixed by the call
        let mut init: Subst = vec![None; n];
        for (k, fx) in fixed.iter().enumerate() {
            if let Some(ty) = fx.and_then(|i| targs.get(i)) {
                init[k] = Some(self.ty(ty, span)?);
            }
        }
        // the facts in scope, as terms at depth `d` (conjuncts too)
        let hidden = self.f.scope.hidden.clone();
        let mut facts: Vec<Tm> = Vec::new();
        for fr in &self.f.scope.facts {
            let l = fr.lvl.0;
            if hidden.contains(&l) {
                continue;
            }
            if let Some(ft) = self.f.scope.fact_tys.get(&l) {
                conjuncts(&shift(ft, (d - l) as i64), &mut facts);
            }
        }
        let goal_t = goal.map(|g| g.at(d));
        let hyps: Vec<usize> = (0..n).filter(|k| kinds[*k] == B::Hyp).collect();
        // per hypothesis: the facts it matches, with the instantiation
        let mut m = Matcher { el: self, kinds: &kinds, fuel: FUEL };
        let mut per_hyp: Vec<Vec<(usize, Subst)>> = Vec::new();
        for &k in &hyps {
            let mut v = Vec::new();
            for (fi, ft) in facts.iter().enumerate() {
                let mut s = init.clone();
                if m.mt(&doms[k].1, k as u32, ft, 0, &mut s) {
                    v.push((fi, s));
                }
            }
            per_hyp.push(v);
        }
        let goal_sub = goal_t.as_ref().and_then(|gt| {
            let mut s = init.clone();
            m.mt(&concl_pat, n as u32, gt, 0, &mut s).then_some(s)
        });
        let exhausted = m.fuel == 0;
        // combine: every hypothesis uses one matching fact or is left to the
        // prover; keep the complete instantiations using the most facts
        struct Sol {
            s: Subst,
            used: usize,
            facts: Vec<Option<usize>>,
            goal: bool,
        }
        let mut sols: Vec<Sol> = Vec::new();
        let mut nodes = 0u32;
        #[allow(clippy::too_many_arguments)]
        fn dfs(m: &Matcher, per_hyp: &[Vec<(usize, Subst)>], goal_sub: &Option<Subst>, kinds: &[B], j: usize, cur: Subst, used: usize, chosen: &mut Vec<Option<usize>>, sols: &mut Vec<Sol>, nodes: &mut u32) {
            *nodes += 1;
            if *nodes > SEARCH || sols.len() > 64 {
                return;
            }
            if j == per_hyp.len() {
                let (fin, used, goal) = match goal_sub.as_ref().and_then(|g| merge(m, &cur, g)) {
                    Some(x) => (x, used + 1, true),
                    None => (cur, used, false),
                };
                if fin.iter().zip(kinds).all(|(x, k)| *k == B::Hyp || x.is_some()) {
                    sols.push(Sol { s: fin, used, facts: chosen.clone(), goal });
                }
                return;
            }
            for (fi, s) in &per_hyp[j] {
                if let Some(mm) = merge(m, &cur, s) {
                    chosen.push(Some(*fi));
                    dfs(m, per_hyp, goal_sub, kinds, j + 1, mm, used + 1, chosen, sols, nodes);
                    chosen.pop();
                }
            }
            chosen.push(None);
            dfs(m, per_hyp, goal_sub, kinds, j + 1, cur, used, chosen, sols, nodes);
            chosen.pop();
        }
        dfs(&m, &per_hyp, &goal_sub, &kinds, 0, init.clone(), 0, &mut Vec::new(), &mut sols, &mut nodes);
        let best = sols.iter().map(|x| x.used).max().unwrap_or(0);
        let mut distinct: Vec<&Sol> = Vec::new();
        for x in sols.iter().filter(|x| x.used == best) {
            let dup = distinct.iter().any(|y| x.s.iter().zip(&y.s).all(|(a, b)| match (a, b) {
                (Some(a), Some(b)) => m.same_term(a, b),
                (None, None) => true,
                _ => false,
            }));
            if !dup {
                distinct.push(x);
            }
        }
        // telescope names for printing patterns
        let tele_names: Vec<Name> = doms.iter().map(|(_, _, nm)| nm.clone()).collect();
        let show_pat = |me: &Self, t: &Tm, k: usize| -> String { sandblaster_kernel::syntax::printer::print_term_bounded(&me.env, &tele_names[..k], t, 400) };
        let meta_names: Vec<String> = (0..n).filter(|k| kinds[*k] == B::Meta && fixed[*k].is_none()).map(|k| tele_names[k].to_string()).collect();
        let chosen = match distinct.as_slice() {
            [one] if best > 0 || meta_names.is_empty() => (one.s.clone(), one.facts.clone(), one.goal),
            [] | [_] => {
                let mut dg = Diagnostic::error(DiagKind::Script, span, format!("`apply({lname})`: cannot infer its arguments ({})", meta_names.join(", ")));
                if hyps.is_empty() {
                    dg = dg.note(format!("`{lname}` has no `requires` to match: its arguments can only come from its `ensures` matching the goal"));
                }
                for (j, &k) in hyps.iter().enumerate() {
                    let pat = show_pat(self, &doms[k].1, k);
                    let hits = per_hyp[j].len();
                    dg = dg.note(format!("requires: {pat}  — {}", if hits == 0 { "no fact in scope matches".to_string() } else { format!("{hits} matching fact(s)") }));
                }
                if let Some(gt) = &goal_t {
                    dg = dg.note(format!("ensures: {}  — {} the goal `{}`", show_pat(self, &concl_pat, n), if goal_sub.is_some() { "matches" } else { "does not match" }, trunc(self.show_tm(gt))));
                }
                if facts.is_empty() {
                    dg = dg.note("no facts in scope");
                }
                for ft in facts.iter().take(12) {
                    dg = dg.note(format!("fact in scope: {}", trunc(self.show_tm(ft))));
                }
                if exhausted {
                    dg = dg.note("matching ran out of its work limit");
                }
                dg = dg.note(format!("pass the arguments explicitly: `{lname}(..);`"));
                self.diags.push(dg);
                self.f.failed = true;
                return Err(ElabError { span, msg: format!("`apply({lname})` could not infer its arguments"), kind: ErrKind::Unsupported });
            }
            many => {
                let mut dg = Diagnostic::error(DiagKind::Script, span, format!("`apply({lname})` is ambiguous: {} instantiations match equally well", many.len()));
                for (ci, sol) in many.iter().take(8).enumerate() {
                    let binds: Vec<String> = (0..n).filter(|k| kinds[*k] == B::Meta && fixed[*k].is_none()).map(|k| format!("{} = {}", tele_names[k], sol.s[k].as_ref().map(|t| trunc(self.show_tm(t))).unwrap_or_else(|| "?".into()))).collect();
                    dg = dg.note(format!("candidate {}: {}", ci + 1, binds.join(", ")));
                }
                dg = dg.note(format!("pass the arguments explicitly: `{lname}(..);`"));
                self.diags.push(dg);
                self.f.failed = true;
                return Err(ElabError { span, msg: format!("`apply({lname})` is ambiguous"), kind: ErrKind::Unsupported });
            }
        };
        let (sub, _used_facts, _goal) = chosen;
        // the application, as for an explicit call: hypotheses by the prover
        let callee_kind = ObligationKind::CalleeRequires(g);
        let mut app_t = mk::global(g);
        let mut all: Vec<Tm> = Vec::new();
        for (k, (rel, dom, _)) in doms.iter().enumerate() {
            let arg = match kinds[k] {
                B::Meta => sub[k].clone().ok_or_else(|| ElabError { span, msg: "`apply`: unbound argument".into(), kind: ErrKind::Internal })?,
                B::Hyp => {
                    let target = super::super::tm::subst_closed(dom, &all);
                    let target = super::super::recert::recertify(&self.env, &self.f.scope.ctx, &target);
                    self.prove(callee_kind.clone(), span, &target, relevant && *rel == Rel::Rel)?
                }
            };
            app_t = Rc::new(Term::App { rel: *rel, fun: app_t, arg: arg.clone() });
            all.push(arg);
        }
        let concl = super::super::tm::subst_closed(&concl_pat, &all);
        let concl = super::super::recert::recertify(&self.env, &self.f.scope.ctx, &concl);
        Ok((app_t, concl))
    }

    /// The facts in scope that fix a variable to a closed value (`x ==
    /// literal` or `x == C(..)` without variables, either orientation;
    /// conjunctions split): `(variable level, value, its type, proof of
    /// Eq(type, value, x))`, all terms at the current depth. The first fact
    /// for a variable wins.
    fn fixed_variables(&self) -> Vec<(u32, Tm, Tm, Tm)> {
        let d = self.depth();
        let sc = &self.f.scope;
        let closed = |t: &Tm| matches!(&**t, Term::Lit { .. } | Term::Ctor { .. }) && !super::super::tm::any_node_depth(t, &mut |n, b| matches!(n, Term::Var(Idx(i)) if *i >= b));
        let mut out: Vec<(u32, Tm, Tm, Tm)> = Vec::new();
        let mut work: Vec<(Tm, Tm, u32)> = Vec::new();
        for fr in &sc.facts {
            let l = fr.lvl.0;
            if sc.hidden.contains(&l) {
                continue;
            }
            let Some(t) = sc.fact_tys.get(&l) else { continue };
            work.push((mk::var(d - 1 - l), shift(t, (d - l) as i64), 0));
        }
        while let Some((h, t, n)) = work.pop() {
            match &*t {
                Term::Let { val, body, .. } => work.push((h, super::super::tm::subst0(body, val), n)),
                Term::Sigma { fst, snd, .. } if n < 8 => {
                    work.push((mk::fst(h.clone()), fst.clone(), n + 1));
                    work.push((mk::snd(h.clone()), super::super::tm::subst0(snd, &mk::fst(h)), n + 1));
                }
                // the boolean form `(x == v) == true` of an integer
                // equation: `wN::eq_sound` gives `x == v`
                Term::Eq { ty, lhs, rhs }
                    if matches!(&**ty, Term::Ind { ind, .. } if *ind == self.p.bool_)
                        && matches!(&**rhs, Term::Ctor { ctor: 1, .. })
                        && let Term::Prim { op: sandblaster_kernel::term::PrimOp::Eq(w), args, .. } = &**lhs
                        && args.len() == 2
                        && let Some(snd) = self.env.lookup_global(&format!("{}::eq_sound", sandblaster_kernel::prim::width_suffix(*w))) =>
                {
                    let wt = mk::int_ty(*w);
                    let (a, b) = (&args[0], &args[1]);
                    let ab = mk::apps(mk::global(snd), [(Rel::Rel, a.clone()), (Rel::Rel, b.clone()), (Rel::Irr, h.clone())]);
                    work.push((ab, mk::eq(wt, a.clone(), b.clone()), n + 1));
                }
                Term::Eq { ty, lhs, rhs } => {
                    let sym = |a: &Tm, b: &Tm, p: &Tm| mk::apps(mk::global(self.p.g("eq::sym")), [(Rel::Rel, ty.clone()), (Rel::Rel, a.clone()), (Rel::Rel, b.clone()), (Rel::Rel, p.clone())]);
                    let (x, v, pf) = match (&**lhs, &**rhs) {
                        (Term::Var(Idx(i)), _) if closed(rhs) => (*i, rhs.clone(), sym(lhs, rhs, &h)),
                        (_, Term::Var(Idx(i))) if closed(lhs) => (*i, lhs.clone(), h.clone()),
                        _ => continue,
                    };
                    let lvl = d - 1 - x;
                    if !out.iter().any(|o| o.0 == lvl) {
                        out.push((lvl, v, ty.clone(), pf));
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// `by_computation()`: the goal holds by evaluation and conversion —
    /// after replacing the variables that facts fix to literals or
    /// constructors (`requires(e == 0)`) by their values.
    pub(super) fn by_computation(&mut self, goal: Val, kind: ObligationKind, sp: Span) -> R<Tm> {
        let d = self.depth();
        let g = goal.at(d);
        let gv = self.eval(&g)?;
        let id = self.obligations.len() as u32;
        let why: Vec<String> = match &*gv {
            Value::Eq { ty, lhs, rhs } => {
                let mut b = self.budget();
                let direct = self.env.conv(Lvl(d), lhs, rhs, &mut b);
                // the variables the facts fix, substituted in the goal term
                // (`transport` along each fact): evaluation still decides
                let fixed = if matches!(direct, Ok(true)) { None } else { self.substituted_goal(&g) };
                if let Some((g2, wrap)) = fixed
                    && let Ok(Value::Eq { ty: t2, lhs: l2, rhs: r2 }) = self.eval(&g2).as_deref()
                    && self.env.conv(Lvl(d), l2, r2, &mut self.budget()).unwrap_or(false)
                {
                    let proof = match &*g2 {
                        Term::Eq { ty, lhs, .. } => mk::refl(ty.clone(), lhs.clone()),
                        _ => mk::refl(self.quote(t2, None), self.quote(l2, None)),
                    };
                    let proof = wrap(proof);
                    if self.check_proof(&proof, &g, self.f.mode == Mode::Proof).is_ok() {
                        self.record(id, kind, sp, super::super::OblStatus::Proven { by: "script(by_computation)".into() }, true, String::new());
                        return Ok(proof);
                    }
                }
                match direct {
                    Ok(true) => {
                        let proof = match &*g {
                            Term::Eq { ty, lhs, .. } => mk::refl(ty.clone(), lhs.clone()),
                            _ => mk::refl(self.quote(ty, None), self.quote(lhs, None)),
                        };
                        self.record(id, kind, sp, super::super::OblStatus::Proven { by: "script(by_computation)".into() }, true, String::new());
                        return Ok(proof);
                    }
                    r => {
                        let names = self.f.scope.names();
                        let l = super::super::show::value(&self.env, &names, lhs, 600);
                        let rr = super::super::show::value(&self.env, &names, rhs, 600);
                        let mut v = vec![format!("left side evaluates to: {l}"), format!("right side evaluates to: {rr}")];
                        v.push(match r {
                            Err(_) => "evaluation ran out of its budget".into(),
                            _ => "the evaluated sides differ: the goal needs facts or reasoning beyond evaluation (`by_arithmetic()`, `by_unfolding(..)`, `follows()` or more steps)".into(),
                        });
                        v
                    }
                }
            }
            Value::Ind { ind, .. } if *ind == self.p.unit => {
                self.record(id, kind, sp, super::super::OblStatus::Proven { by: "script(by_computation)".into() }, true, String::new());
                return Ok(self.unit_val());
            }
            _ => vec!["`by_computation()` proves an equation (or a `bool` goal) whose two sides evaluate to the same value".into()],
        };
        let failure = AutoFailure { tried: vec!["`by_computation()`: evaluation only, no proof search".into()], ..Default::default() };
        self.fail_obligation(id, kind, sp, &g, failure, true);
        if let Some(dg) = self.diags.list.last_mut() {
            for w in why {
                dg.notes.push((None, w));
            }
        }
        Ok(Rc::new(Term::Erased))
    }

    /// The goal term `g` with the variables that facts fix to closed values
    /// substituted ([`Elab::fixed_variables`]), and the function turning a
    /// proof of the substituted goal into a proof of `g` (a `transport`
    /// along each fact). `None` if no fixed variable occurs in `g`.
    #[allow(clippy::type_complexity)]
    fn substituted_goal(&mut self, g: &Tm) -> Option<(Tm, Box<dyn Fn(Tm) -> Tm>)> {
        let d = self.depth();
        let mut cur = g.clone();
        let mut steps: Vec<(Tm, Tm, Tm, Tm, Tm)> = Vec::new();
        for (lvl, v, ty, pf) in self.fixed_variables() {
            let x = mk::var(d - 1 - lvl);
            if !occurs(&cur, d - 1 - lvl) {
                continue;
            }
            // `cur[x := y]` at depth `d + 1` (`y` is `Var(0)`)
            let m = super::abstract_level(&cur, d, lvl);
            // the motive must be a proposition over the generalized variable
            let Ok(tv) = self.eval(&ty) else { continue };
            let saved = self.f.scope.clone();
            self.push_v("y", Rel::Rel, tv);
            let mut b = self.budget();
            let ok = matches!(self.env.infer(&self.f.scope.ctx, &m, &mut b), Ok(t) if matches!(&*t, Value::Sort(_)));
            self.f.scope = saved;
            if !ok {
                continue;
            }
            cur = super::super::tm::simp_redexes(&super::super::tm::subst0(&m, &v));
            steps.push((ty, v, x, pf, m));
        }
        if steps.is_empty() {
            return None;
        }
        // transport(A, v, x, e : Eq(A, v, x), m, p : m[v]) : m[x]
        Some((
            cur,
            Box::new(move |p: Tm| {
                let mut p = p;
                for (ty, v, x, e, m) in steps.iter().rev() {
                    p = Rc::new(Term::Transport { ty: ty.clone(), lhs: v.clone(), rhs: x.clone(), eq: e.clone(), motive: m.clone(), val: p });
                }
                p
            }),
        ))
    }

    /// A `calc!` chain: proves every link, then `concl` (by transport for
    /// `==` chains, by the prover over the links for `<=`/`<` chains), and
    /// continues with `k(concl, proof)`.
    pub(super) fn calc_chain(&mut self, links: &'a [CalcLink], concl: &'a Expr, rel: CalcRel, sp: Span, k: &mut dyn FnMut(&mut Elab<'a>, Tm, Tm) -> R<Tm>) -> R<Tm> {
        let relevant = self.f.mode == Mode::Proof;
        if rel == CalcRel::Eq {
            let d = self.depth();
            // (type, first term, last term, proof of `first == last`)
            let mut acc: Option<(Tm, Tm, Tm, Tm)> = None;
            let mut lifted = false;
            let failed_from = self.obligations.len();
            for l in links {
                let p = self.prop(&l.prop)?;
                let pf = self.calc_link(l, &p, relevant)?;
                let (ty, lhs, rhs) = match &*p {
                    Term::Eq { ty, lhs, rhs } => (ty.clone(), lhs.clone(), rhs.clone()),
                    _ => match &*self.eval(&p)? {
                        Value::Eq { ty, lhs, rhs } => (self.quote(ty, None), self.quote(lhs, None), self.quote(rhs, None)),
                        _ => return internal(l.span, "`calc!`: a `==` link is not an equation"),
                    },
                };
                acc = Some(match acc {
                    None => (ty, lhs, rhs, pf),
                    Some((a, e0, last, q)) => {
                        // a view link (`exec == spec`, an equation at the
                        // spec type between `view(last)` and a spec value)
                        // after exec links: the chain so far is lifted
                        // through the view first (`view(e0) == view(last)`,
                        // by transport along it from `refl`)
                        let (a, e0, q, lift) = self.calc_lift(&a, &e0, &last, q, &ty, &lhs);
                        lifted |= lift;
                        // transitivity: transport `e0 == e(i-1)` along `e(i-1) == e(i)`
                        let motive = mk::eq(shift(&a, 1), shift(&e0, 1), mk::var(0));
                        (a.clone(), e0, rhs.clone(), Rc::new(Term::Transport { ty: a, lhs, rhs, eq: pf, motive, val: q }))
                    }
                });
            }
            debug_assert_eq!(self.depth(), d);
            let Some((a_fin, e0_fin, last_fin, pf)) = acc else { return internal(sp, "empty `calc!`") };
            let c = self.prop(concl)?;
            // the composed relation must be the chain's conclusion (always
            // checked, before any transport reaches the kernel): a chain
            // that goes from exec values through a spec value and back
            // composes only at the spec type (`view(a) == view(b)`), which
            // is not `a == b` without the view's injectivity
            let composed = mk::eq(a_fin.clone(), e0_fin, last_fin);
            let agrees = match (self.eval(&composed), self.eval(&c)) {
                (Ok(x), Ok(y)) => self.env.conv(sandblaster_kernel::term::Lvl(self.depth()), &x, &y, &mut self.budget()).unwrap_or(false),
                _ => false,
            };
            if !agrees {
                let id = self.obligations.len() as u32;
                let failure = AutoFailure { tried: vec![format!("`calc!`: the links compose to {}, not to {}", trunc(self.show_tm(&composed)), trunc(self.show_tm(&c)))], ..Default::default() };
                self.fail_obligation(id, ObligationKind::Assert, sp, &c, failure, true);
                let c_ty = match self.eval(&c) {
                    Ok(v) => match &*v {
                        Value::Eq { ty, .. } => Some(self.quote(ty, None)),
                        _ => None,
                    },
                    Err(_) => None,
                };
                let same_ty = c_ty.as_ref().is_some_and(|t| match (self.eval(t), self.eval(&a_fin)) {
                    (Ok(x), Ok(y)) => self.env.conv(sandblaster_kernel::term::Lvl(self.depth()), &x, &y, &mut self.budget()).unwrap_or(false),
                    _ => false,
                });
                let note = if same_ty {
                    "each link's left side must be the previous link's right side, and the chain's first and last terms the two sides of its conclusion".to_string()
                } else {
                    format!(
                        "the chain composes at `{}`, the conclusion compares values of `{}`: a chain that goes from exec values to a spec value and back proves only that their views are equal; conclude `a == b` from it with the view's injectivity (`#[proof(view_inj = T)]`, DESIGN.md §15.2)",
                        trunc(self.show_tm(&a_fin)),
                        c_ty.as_ref().map(|t| trunc(self.show_tm(t))).unwrap_or_else(|| "?".into())
                    )
                };
                if let Some(dg) = self.diags.list.last_mut() {
                    dg.notes.push((None, note));
                }
                return k(self, c, Rc::new(Term::Erased));
            }
            // a chain lifted through a view must prove the statement it
            // concludes (links whose types do not compose are reported
            // here, not by the kernel); a link that failed has already been
            // reported (its proof is a placeholder): the chain is not blamed
            // for it
            let link_failed = self.obligations[failed_from..].iter().any(|o| !o.proven());
            if lifted
                && !link_failed
                && !super::super::tm::any_node(&pf, &mut |n| matches!(n, Term::Rec { .. }))
                && let Err(e) = self.check_proof(&pf, &c, relevant)
            {
                let id = self.obligations.len() as u32;
                let failure = AutoFailure { tried: vec![format!("`calc!`: the links do not compose to {}: {}", trunc(self.show_tm(&c)), trunc(e))], ..Default::default() };
                self.fail_obligation(id, ObligationKind::Assert, sp, &c, failure, true);
                if let Some(dg) = self.diags.list.last_mut() {
                    dg.notes.push((None, "each link's left side must be the previous link's right side (a view link `exec == spec` may follow links between exec values)".into()));
                }
                return k(self, c, Rc::new(Term::Erased));
            }
            return k(self, c, pf);
        }
        self.calc_facts(links, 0, concl, sp, relevant, k)
    }

    /// The chain so far (`q : Eq(a, e0, last)`) adapted to the next link's
    /// type `ty` and left side `lhs`: unchanged when the types agree;
    /// otherwise, when `lhs` is `last` under a context `V[_]` (the view of
    /// an exec value), `V[e0] == V[last]` at `ty` (transport along `q` from
    /// `refl(V[e0])`). The result's type is checked where the chain ends.
    fn calc_lift(&mut self, a: &Tm, e0: &Tm, last: &Tm, q: Tm, ty: &Tm, lhs: &Tm) -> (Tm, Tm, Tm, bool) {
        let same = match (self.eval(a), self.eval(ty)) {
            (Ok(x), Ok(y)) => self.env.conv(Lvl(self.depth()), &x, &y, &mut self.budget()).unwrap_or(false),
            _ => true,
        };
        if same {
            return (a.clone(), e0.clone(), q, false);
        }
        let Some(ctxt) = super::super::tm::abstract_syntactic(&self.env, lhs, last) else { return (a.clone(), e0.clone(), q, true) };
        let v_e0 = super::super::tm::subst0(&ctxt, e0);
        // motive `Eq(ty, V[e0], V[y])` over `y : a`
        let motive = mk::eq(shift(ty, 1), shift(&v_e0, 1), ctxt.clone());
        let lifted = Rc::new(Term::Transport { ty: a.clone(), lhs: e0.clone(), rhs: last.clone(), eq: q, motive, val: mk::refl(ty.clone(), v_e0.clone()) });
        (ty.clone(), v_e0, lifted, true)
    }

    fn calc_link(&mut self, l: &'a CalcLink, p: &Tm, relevant: bool) -> R<Tm> {
        match &l.steps {
            Some(ss) => self.script(ss, Val::new(p.clone(), self.depth()), ObligationKind::Assert, l.span),
            None => {
                let _ = relevant;
                self.close_implicit(Val::new(p.clone(), self.depth()), ObligationKind::Assert, l.span, l.span, super::OpenEnd::CalcLink)
            }
        }
    }

    fn calc_facts(&mut self, links: &'a [CalcLink], i: usize, concl: &'a Expr, sp: Span, relevant: bool, k: &mut dyn FnMut(&mut Elab<'a>, Tm, Tm) -> R<Tm>) -> R<Tm> {
        let Some(l) = links.get(i) else {
            let c = self.prop(concl)?;
            let pf = self.prove(ObligationKind::Assert, sp, &c, relevant)?;
            return k(self, c, pf);
        };
        let p = self.prop(&l.prop)?;
        let pf = self.calc_link(l, &p, relevant)?;
        self.fact_in("h_calc", p, pf, FactOrigin::Assert, l.span, &mut |s| s.calc_facts(links, i + 1, concl, sp, relevant, k))
    }

    /// The end of a script with a `calc!` chain: its conclusion must be the
    /// goal.
    pub(super) fn calc_close(&mut self, goal: &Val, concl: &Tm, pf: Tm, kind: ObligationKind, sp: Span) -> R<Tm> {
        let d = self.depth();
        let g = goal.at(d);
        let id = self.obligations.len() as u32;
        let (gv, cv) = (self.eval(&g)?, self.eval(concl)?);
        let mut b = self.budget();
        if self.env.conv(Lvl(d), &gv, &cv, &mut b).unwrap_or(false) {
            self.record(id, kind, sp, super::super::OblStatus::Proven { by: "script(calc)".into() }, true, String::new());
            return Ok(pf);
        }
        let failure = AutoFailure { tried: vec![format!("`calc!` proves {}", trunc(self.show_tm(concl)))], ..Default::default() };
        self.fail_obligation(id, kind, sp, &g, failure, true);
        if let Some(dg) = self.diags.list.last_mut() {
            dg.notes.push((None, "the chain's first and last terms must be the two sides of the goal (a `calc!` in the middle of a proof only adds its conclusion as a fact)".into()));
        }
        Ok(Rc::new(Term::Erased))
    }
}

fn trunc(s: String) -> String {
    if s.len() <= 300 {
        return s;
    }
    let mut cut = 300;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &s[..cut])
}
