//! Codegen-facing checks (DESIGN.md §5.11, §8.3).
//!
//! * [`alpha_eq_relevant`]: syntactic α-equivalence ignoring binder names and
//!   every irrelevant position (irrelevant application arguments, `Irr` let
//!   values, prim proof slots, `Rec` proofs, `Transport.eq`, `Absurd.proof`,
//!   `Irr` constructor fields, the second component of a pair whose Σ is
//!   `Irr`, irrelevant arguments of `Delta`/`Unfold`/axioms/`Rec`). It never
//!   evaluates terms (except to find the Σ of a pair whose type is not
//!   syntactically a Σ), so hoisting, dropping or duplicating an operation
//!   makes it fail.
//! * [`check_residual_equal`]: a straight-line candidate (no relevant
//!   `Match`, `Rec` or `Absurd`) with `Erased` allowed in irrelevant
//!   positions is checked at the reference's type and must be convertible
//!   with the reference — in the optimizer's transparent mode, so opaque
//!   definitions unfold (DESIGN.md §5.6). It is never added to the
//!   environment.

use std::rc::Rc;

use crate::api::{Env, KernelErrorKind as K};
use crate::check::{Checker, Cx, KR, kerr};
use crate::conv::Conv;
use crate::eval::{Ev, var_v};
use crate::term::{GlobalId, Idx, Lvl, Rel, Term, Tm};
use crate::util::{any_sub, children};
use crate::value::{Budget, EnvEntry, VEnv, Value};

/// Number of free variables a term may refer to (max free index + 1).
fn free_extent(t: &Tm) -> u32 {
    let mut m = 0u32;
    any_sub(t, 0, &mut |n, d| {
        if let Term::Var(Idx(i)) = &**n
            && *i >= d
        {
            m = m.max(i - d + 1);
        }
        false
    });
    m
}

/// Relevance of the second component of a pair of type `ty` (evaluating `ty`
/// over fresh variables when it is not syntactically a Σ; `Rel` if unknown).
pub(crate) fn pair_snd_rel(env: &Env, ty: &Tm) -> Rel {
    if let Term::Sigma { snd_rel, .. } = &**ty {
        return *snd_rel;
    }
    let n = free_extent(ty);
    let venv = VEnv(Rc::new((0..n).map(|l| EnvEntry::Rel(var_v(Lvl(l)))).collect()));
    let mut b = Budget { steps: 100_000 };
    match Ev::new(env).eval(&venv, Lvl(n), ty, &mut b) {
        Ok(v) => match &*v {
            Value::Sigma { snd_rel, .. } => *snd_rel,
            _ => Rel::Rel,
        },
        Err(_) => Rel::Rel,
    }
}

fn ctor_rels(env: &Env, ind: crate::term::IndId, ctor: u32) -> Vec<Rel> {
    env.ctor_rels(ind, ctor).unwrap_or_default()
}

fn rel_at(rels: &[Rel], i: usize) -> Rel {
    rels.get(i).copied().unwrap_or(Rel::Rel)
}

struct Alpha<'a> {
    env: &'a Env,
    corr: &'a dyn Fn(GlobalId, GlobalId) -> bool,
    /// Relevances of the leading λ binders of the compared terms (used for
    /// `Rec` arguments, which are full applications of that telescope).
    rec_rels: Vec<Rel>,
    /// Pairs of shared nodes already found equal (both terms are borrowed
    /// for the whole comparison, so addresses are stable). α-equivalence of
    /// de Bruijn terms does not depend on the binder depth, so a pair equal
    /// once is equal wherever it recurs: term DAGs are compared in linear
    /// time.
    same: std::cell::RefCell<crate::util::FxSet<(usize, usize)>>,
}

fn taddr(t: &Tm) -> usize {
    Rc::as_ptr(t) as *const () as usize
}

impl Alpha<'_> {
    fn list(&self, a: &[Tm], b: &[Tm], rels: &[Rel]) -> bool {
        a.len() == b.len() && a.iter().zip(b).enumerate().all(|(i, (x, y))| rel_at(rels, i) == Rel::Irr || self.eq(x, y))
    }

    fn eq(&self, a: &Tm, b: &Tm) -> bool {
        if Rc::ptr_eq(a, b) {
            return true;
        }
        let shared = Rc::strong_count(a) > 1 || Rc::strong_count(b) > 1;
        if shared && self.same.borrow().contains(&(taddr(a), taddr(b))) {
            return true;
        }
        let r = self.eq_node(a, b);
        if r && shared {
            self.same.borrow_mut().insert((taddr(a), taddr(b)));
        }
        r
    }

    fn eq_node(&self, a: &Tm, b: &Tm) -> bool {
        use Term::*;
        match (&**a, &**b) {
            (Var(i), Var(j)) => i == j,
            (Global(g), Global(h)) => (self.corr)(*g, *h),
            (Sort(s), Sort(t)) => s == t,
            (Pi { rel: r1, dom: d1, cod: c1, .. }, Pi { rel: r2, dom: d2, cod: c2, .. })
            | (Lam { rel: r1, dom: d1, body: c1, .. }, Lam { rel: r2, dom: d2, body: c2, .. }) => {
                r1 == r2 && self.eq(d1, d2) && self.eq(c1, c2)
            }
            (App { rel: r1, fun: f1, arg: a1 }, App { rel: r2, fun: f2, arg: a2 }) => {
                r1 == r2 && self.eq(f1, f2) && (*r1 == Rel::Irr || self.eq(a1, a2))
            }
            (Let { rel: r1, ty: t1, val: v1, body: b1, .. }, Let { rel: r2, ty: t2, val: v2, body: b2, .. }) => {
                r1 == r2 && self.eq(t1, t2) && (*r1 == Rel::Irr || self.eq(v1, v2)) && self.eq(b1, b2)
            }
            (Sigma { snd_rel: r1, fst: f1, snd: s1, .. }, Sigma { snd_rel: r2, fst: f2, snd: s2, .. }) => {
                r1 == r2 && self.eq(f1, f2) && self.eq(s1, s2)
            }
            (Pair { ty: t1, fst: f1, snd: s1 }, Pair { ty: t2, fst: f2, snd: s2 }) => {
                self.eq(t1, t2) && self.eq(f1, f2) && (pair_snd_rel(self.env, t1) == Rel::Irr || self.eq(s1, s2))
            }
            (Fst(p), Fst(q)) | (Snd(p), Snd(q)) => self.eq(p, q),
            (Eq { ty: t1, lhs: l1, rhs: r1 }, Eq { ty: t2, lhs: l2, rhs: r2 }) => self.eq(t1, t2) && self.eq(l1, l2) && self.eq(r1, r2),
            (Refl { ty: t1, val: v1 }, Refl { ty: t2, val: v2 }) => self.eq(t1, t2) && self.eq(v1, v2),
            (
                Transport { ty: t1, lhs: l1, rhs: r1, motive: m1, val: v1, .. },
                Transport { ty: t2, lhs: l2, rhs: r2, motive: m2, val: v2, .. },
            ) => self.eq(t1, t2) && self.eq(l1, l2) && self.eq(r1, r2) && self.eq(m1, m2) && self.eq(v1, v2),
            (Ind { ind: i1, params: p1 }, Ind { ind: i2, params: p2 }) => i1 == i2 && self.list(p1, p2, &[]),
            (Ctor { ind: i1, ctor: c1, params: p1, args: a1 }, Ctor { ind: i2, ctor: c2, params: p2, args: a2 }) => {
                i1 == i2 && c1 == c2 && self.list(p1, p2, &[]) && self.list(a1, a2, &ctor_rels(self.env, *i1, *c1))
            }
            (
                Match { ind: i1, params: p1, scrut: s1, motive: m1, arms: a1 },
                Match { ind: i2, params: p2, scrut: s2, motive: m2, arms: a2 },
            ) => {
                i1 == i2
                    && self.list(p1, p2, &[])
                    && self.eq(s1, s2)
                    && self.eq(m1, m2)
                    && a1.len() == a2.len()
                    && a1.iter().zip(a2).all(|(x, y)| x.names.len() == y.names.len() && self.eq(&x.body, &y.body))
            }
            (IntTy(w1), IntTy(w2)) => w1 == w2,
            (Lit { w: w1, n: n1 }, Lit { w: w2, n: n2 }) => w1 == w2 && n1 == n2,
            (Prim { op: o1, args: a1, proofs: q1 }, Prim { op: o2, args: a2, proofs: q2 }) => {
                o1 == o2 && q1.len() == q2.len() && self.list(a1, a2, &[])
            }
            (Rec { args: a1, .. }, Rec { args: a2, .. }) => {
                let rels = if self.rec_rels.len() >= a1.len() { self.rec_rels[..a1.len()].to_vec() } else { vec![] };
                self.list(a1, a2, &rels)
            }
            (Delta { def: d1, args: a1 }, Delta { def: d2, args: a2 }) => (self.corr)(*d1, *d2) && self.list(a1, a2, &self.def_rels(*d1)),
            (Unfold { def: d1, args: a1, to_body: t1, val: v1 }, Unfold { def: d2, args: a2, to_body: t2, val: v2 }) => {
                (self.corr)(*d1, *d2) && t1 == t2 && self.list(a1, a2, &self.def_rels(*d1)) && self.eq(v1, v2)
            }
            (Linarith { hyps: h1, goal: g1, cert: c1 }, Linarith { hyps: h2, goal: g2, cert: c2 }) => {
                h1.len() == h2.len()
                    && h1.iter().zip(h2).all(|((p1, s1), (p2, s2))| self.eq(p1, p2) && self.eq(s1, s2))
                    && self.eq(g1, g2)
                    && c1 == c2
            }
            (BvRefl { ty: t1, lhs: l1, rhs: r1 }, BvRefl { ty: t2, lhs: l2, rhs: r2 }) => {
                self.eq(t1, t2) && self.eq(l1, l2) && self.eq(r1, r2)
            }
            (Absurd { ty: t1, .. }, Absurd { ty: t2, .. }) => self.eq(t1, t2),
            (Axiom { ax: x1, args: a1 }, Axiom { ax: x2, args: a2 }) => {
                x1 == x2 && self.list(a1, a2, &crate::axioms::axiom_param_rels(*x1))
            }
            (Erased, Erased) => true,
            _ => false,
        }
    }

    fn def_rels(&self, g: GlobalId) -> Vec<Rel> {
        self.env.defs.get(g.0 as usize).map(|d| d.param_rels.clone()).unwrap_or_default()
    }
}

fn leading_lam_rels(t: &Tm) -> Vec<Rel> {
    let mut out = Vec::new();
    let mut t = t.clone();
    while let Term::Lam { rel, body, .. } = &*t.clone() {
        out.push(*rel);
        t = body.clone();
    }
    out
}

pub(crate) fn alpha_eq_relevant(env: &Env, a: &Tm, b: &Tm, corr: &dyn Fn(GlobalId, GlobalId) -> bool) -> bool {
    let ra = leading_lam_rels(a);
    let rb = leading_lam_rels(b);
    let rec_rels = if ra == rb { ra } else { vec![] };
    Alpha { env, corr, rec_rels, same: Default::default() }.eq(a, b)
}

/// Reject relevant `Match`, `Rec` and `Absurd`, and relevant references to
/// the reference itself or to anything defined after it (the candidate is
/// emitted as the reference's body, so such a call could loop); irrelevant
/// positions may contain anything (they are proofs, erased by codegen).
fn straight_line(env: &Env, t: &Tm, reference: GlobalId) -> Result<(), String> {
    let mut seen = crate::util::FxSet::default();
    straight_line_in(env, t, reference, &mut seen)
}

/// [`straight_line`] with the set of shared nodes already accepted (a term
/// DAG is walked once per node; the check does not depend on binders).
fn straight_line_in(env: &Env, t: &Tm, reference: GlobalId, seen: &mut crate::util::FxSet<usize>) -> Result<(), String> {
    if Rc::strong_count(t) > 1 && seen.contains(&taddr(t)) {
        return Ok(());
    }
    let mut straight_line = |env: &Env, t: &Tm| straight_line_in(env, t, reference, seen);
    let r = straight_line_node(env, t, reference, &mut straight_line);
    if r.is_ok() && Rc::strong_count(t) > 1 {
        seen.insert(taddr(t));
    }
    r
}

fn straight_line_node(
    env: &Env,
    t: &Tm,
    reference: GlobalId,
    straight_line: &mut dyn FnMut(&Env, &Tm) -> Result<(), String>,
) -> Result<(), String> {
    use Term::*;
    match &**t {
        Global(g) if g.0 >= reference.0 => Err(format!(
            "candidate refers to {} (the reference or a later global)",
            env.global_name(*g).map(|n| n.to_string()).unwrap_or_else(|| format!("@{}", g.0))
        )),
        Match { .. } => Err("candidate contains a relevant `match`".into()),
        Rec { .. } => Err("candidate contains `rec`".into()),
        Absurd { .. } => Err("candidate contains a relevant `absurd`".into()),
        App { rel, fun, arg } => {
            straight_line(env, fun)?;
            if *rel == Rel::Rel { straight_line(env, arg) } else { Ok(()) }
        }
        Let { rel, ty, val, body, .. } => {
            straight_line(env, ty)?;
            if *rel == Rel::Rel {
                straight_line(env, val)?;
            }
            straight_line(env, body)
        }
        Pair { ty, fst, snd } => {
            straight_line(env, ty)?;
            straight_line(env, fst)?;
            if pair_snd_rel(env, ty) == Rel::Rel { straight_line(env, snd) } else { Ok(()) }
        }
        Prim { args, .. } => args.iter().try_for_each(|a| straight_line(env, a)),
        Transport { ty, lhs, rhs, motive, val, .. } => [ty, lhs, rhs, motive, val].into_iter().try_for_each(|a| straight_line(env, a)),
        Ctor { ind, ctor, params, args } => {
            params.iter().try_for_each(|a| straight_line(env, a))?;
            let rels = ctor_rels(env, *ind, *ctor);
            args.iter().enumerate().filter(|(i, _)| rel_at(&rels, *i) == Rel::Rel).try_for_each(|(_, a)| straight_line(env, a))
        }
        // Proof terms in relevant positions: their content is irrelevant data.
        Linarith { .. } | BvRefl { .. } | Delta { .. } | Axiom { .. } | Refl { .. } => Ok(()),
        _ => children(t).into_iter().try_for_each(|(c, _)| straight_line(env, c)),
    }
}

pub(crate) fn check_residual_equal(env: &Env, ty: &Tm, candidate: &Tm, reference: GlobalId, b: &mut Budget) -> KR<()> {
    let d = env.defs.get(reference.0 as usize).ok_or_else(|| kerr(K::IllFormed, format!("unknown reference {reference:?}")))?;
    straight_line(env, candidate, reference).map_err(|m| kerr(K::IllFormed, m))?;
    let chk = Checker::with_flags(env, true, false);
    let cx = Cx::default();
    chk.infer_sort(&cx, ty, crate::check::REL, b)?;
    let tyv = chk.eval(&cx, ty, b)?;
    if !chk.conv(&cx, &tyv, &d.ty_val, b)? {
        return Err(kerr(K::TypeMismatch, format!("candidate type differs from the type of `{}`", d.name)));
    }
    chk.check(&cx, candidate, &tyv, crate::check::REL, b)?;
    // The equivalence itself is decided in the optimizer's transparent mode
    // (DESIGN.md §5.6): residuals are produced by `eval_opaque` with opaque
    // definitions unfolded, and unfolding a definition is always sound.
    let cv = Ev::transparent(env).eval(&cx.venv, Lvl(0), candidate, b)?;
    let rv = Ev::transparent(env).eval(&cx.venv, Lvl(0), &crate::util::mk::global(reference), b)?;
    if !Conv::transparent(env).conv(Lvl(0), &cv, &rv, b)? {
        return Err(kerr(K::TypeMismatch, format!("candidate is not convertible with `{}`", d.name)));
    }
    Ok(())
}
