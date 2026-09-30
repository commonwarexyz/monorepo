//! Refining case analysis in scripts (DESIGN.md §4.4 `match`/`if`, §7.6).
//!
//! A script `match` (or `if`) whose scrutinee is a **variable** refines the
//! goal *and the facts that mention the variable* in every arm, like Bend's
//! `match` on a variable (and Lean's `cases`): the dependent facts are
//! reverted into the motive and re-introduced, specialized, in each arm, so
//! a hypothesis `reconstruct_checked(ok, ..) == Some(root)` becomes
//! `reconstruct_checked(false, ..) == Some(root)` in the `false` arm and
//! computes. The superseded originals stay in the kernel context but are
//! hidden from the prover ([`super::Scope::hidden`]).
//!
//! * `bool`, `Option`, enums, structs and tuples: one dependent match on the
//!   variable, motive `λy. Π(e : Eq(D, x, y)). Π(h′ : F[x := y]).. G[x := y]`
//!   applied to `refl` and the reverted facts. Constructor fields become
//!   fresh variables, so nested patterns refine them in turn (a clause
//!   matrix over variables).
//! * `Seq`s: one dependent match on the list (`Nil` / `Cons(head, tail)`),
//!   the prefix patterns `[]`, `[p₁, .., pₖ]`, `[p₁, .., pₖ, rest @ ..]`
//!   peeled one element per `Cons`.
//! * slices: the prelude eliminator `slice::cases` (`[]` / `h :: t`, with
//!   `h :: t` built exactly like the ghost `seq::cons(h, t)`), for the
//!   patterns `[]`, `[p₁, .., pₖ]` and `[p₁, .., pₖ, rest @ ..]`; each case
//!   also gets the path equation and the length fact.
//! * a tuple of distinct variables, `match (a, b) { (p, q) => .. }` (the
//!   pair matches of recursive spec types, §15 S5): one column per
//!   variable, so each arm refines both; a top-level or-pattern is one row
//!   per alternative.
//!
//! Substitution is **syntactic** on the fact and goal *terms* (the variable
//! is replaced, nothing is evaluated), so refining never normalizes a large
//! hypothesis. Patterns outside this fragment (integer literals and ranges,
//! suffix slice patterns, arrays) and non-variable scrutinees fall back to
//! the pattern compiler with the goal unchanged and path equations as facts.

use std::rc::Rc;

use sandblaster_kernel::term::{Arm, Rel, Term, Tm, Width};
use sandblaster_kernel::util::{mk, shift};
use sandblaster_kernel::value::{EnvEntry, VEnv};

use super::{internal, Elab, ElabError, ErrKind, Val, R};
use crate::hir::*;
use crate::prover::{FactOrigin, ObligationKind};
use crate::span::Span;

/// A column pattern of the refinement matrix.
#[derive(Clone, Copy)]
enum CP<'a> {
    Wild,
    Pat(&'a Pat),
    /// The remainder of a slice pattern after its first elements were
    /// matched: `prefix ++ rest`.
    Tail { prefix: &'a [Pat], rest: Option<Option<&'a Pat>> },
}

#[derive(Clone)]
struct Row<'a> {
    pats: Vec<CP<'a>>,
    arm: usize,
    /// HIR locals bound to column variables (by level).
    binds: Vec<(LocalId, u32)>,
}

/// A column: a variable (by level) and its HIR type (references peeled);
/// `local` is the HIR local naming it (the scrutinee), rebound in each arm
/// to the refined value so the arm's steps see it.
#[derive(Clone)]
struct Col {
    lvl: u32,
    ty: Ty,
    local: Option<LocalId>,
}

/// Whether a pattern is in the refinable fragment for a value of type `ty`.
fn supported(p: &Pat, ty: &Ty, el: &Elab<'_>) -> bool {
    let ty = ty.peel_refs();
    match &p.kind {
        PatKind::Wild => true,
        PatKind::Binding { sub, .. } => sub.as_ref().is_none_or(|s| supported(s, ty, el)),
        PatKind::Deref { pat, .. } => supported(pat, ty, el),
        PatKind::Lit(Lit::Bool(_)) => matches!(ty, Ty::Bool),
        PatKind::Lit(_) | PatKind::Range { .. } | PatKind::Or(_) => false,
        PatKind::Tuple(ps) => match ty {
            Ty::Tuple(ts) => ps.len() == ts.len() && ps.iter().zip(ts).all(|(p, t)| supported(p, t, el)),
            _ => false,
        },
        PatKind::Ctor { ctor, fields, .. } => {
            let ci = match ctor {
                Ctor::Struct(_) | Ctor::None => 0,
                Ctor::Some => 1,
                Ctor::Variant(_, v) => *v,
            };
            let Ok(ftys) = el.ctor_field_tys(ty, ci, p.span) else { return false };
            fields.iter().all(|(i, fp)| ftys.get(*i as usize).is_some_and(|ft| supported(fp, ft, el)))
        }
        PatKind::Slice { prefix, rest, suffix } => match ty {
            Ty::Slice(e) | Ty::Seq(e) => {
                suffix.is_empty()
                    && prefix.iter().all(|x| supported(x, e, el))
                    && match rest {
                        None | Some(None) => true,
                        Some(Some(r)) => matches!(&r.kind, PatKind::Binding { sub: None, .. }),
                    }
            }
            _ => false,
        },
    }
}

/// A substitution of context variables (by level) with terms, each given
/// with the depth it was built at.
type Subst<'s> = &'s [(u32, Tm, u32)];

/// `t` (a term at depth `t_depth`) with the variables of `sub` replaced,
/// moved to depth `out_depth ≥ t_depth` (every replacement's depth is at
/// most `out_depth`).
fn subst_levels(t: &Tm, t_depth: u32, sub: Subst<'_>, out_depth: u32) -> Tm {
    super::tm::map_post(t, 0, &mut |n, b| match &*n {
        Term::Var(i) if i.0 >= b => {
            let lvl = t_depth - 1 - (i.0 - b);
            match sub.iter().find(|(l, _, _)| *l == lvl) {
                Some((_, v, vd)) => Some(shift(v, (out_depth - vd + b) as i64)),
                None => Some(Rc::new(Term::Var(sandblaster_kernel::term::Idx(out_depth - 1 - lvl + b)))),
            }
        }
        _ => Some(n),
    })
    .expect("subst_levels")
}

/// The substitution of a refinement at a point where the refined value is
/// `v` (built at depth `vd`) and the reverted facts' new binders start at
/// level `h0`: `x ↦ v`, `hᵢ ↦ Var(h0 + i)`.
fn revert_subst(x: u32, v: &Tm, vd: u32, facts: &[(u32, Tm)], h0: u32, upto: usize) -> Vec<(u32, Tm, u32)> {
    let mut sub = vec![(x, v.clone(), vd)];
    for (i, (l, _)) in facts.iter().enumerate().take(upto) {
        // the i-th new binder, as a variable term at the depth just after it
        sub.push((*l, mk::var(0), h0 + i as u32 + 1));
    }
    sub
}

/// Whether the variable at level `x` occurs in `t` (a term at depth `d`).
fn mentions(t: &Tm, d: u32, x: u32) -> bool {
    super::tm::any_node_depth(t, &mut |n, b| matches!(n, Term::Var(i) if i.0 >= b && d - 1 - (i.0 - b) == x))
}

impl<'a> Elab<'a> {
    /// A refining script `match` (see the module docs); `None` if the
    /// scrutinee or the patterns are outside the refinable fragment.
    #[allow(clippy::too_many_arguments)]
    pub fn refine_match(&mut self, scrut: &'a Expr, pats: &[&'a Pat], steps: &[&'a [ScriptStmt]], goal: &Val, kind: &ObligationKind, span: Span) -> Option<R<Tm>> {
        if let ExprKind::Tuple(es) = &Elab::peel(scrut).kind {
            return self.refine_match_tuple(es, pats, steps, goal, kind, span);
        }
        let x = self.refinable_var(scrut)?;
        let ty = scrut.ty.peel_refs().clone();
        if !matches!(ty, Ty::Bool | Ty::Option(_) | Ty::Adt(..) | Ty::Tuple(_) | Ty::Slice(_) | Ty::Seq(_)) {
            return None;
        }
        if !pats.iter().all(|p| supported(p, &ty, self)) {
            return None;
        }
        let rows: Vec<Row<'a>> = pats.iter().enumerate().map(|(i, p)| Row { pats: vec![CP::Pat(p)], arm: i, binds: vec![] }).collect();
        let local = match &Elab::peel(scrut).kind {
            ExprKind::Local(l) => Some(*l),
            _ => None,
        };
        let cols = vec![Col { lvl: x, ty, local }];
        let g = Val::new(goal.at(self.depth()), self.depth());
        Some(self.refine_compile(cols, rows, steps, g, kind, span))
    }

    /// A refining `match (x₁, .., xₙ) { (p₁, .., pₙ) => .. }` on a tuple of
    /// distinct variables (§15 S5, the pair matches of recursive spec
    /// types): one matrix column per variable, so every arm refines the goal
    /// and the facts in each of them. A top-level or-pattern is one row per
    /// alternative (first-match order is kept). `None` outside that
    /// fragment.
    fn refine_match_tuple(&mut self, es: &'a [Expr], pats: &[&'a Pat], steps: &[&'a [ScriptStmt]], goal: &Val, kind: &ObligationKind, span: Span) -> Option<R<Tm>> {
        let mut cols = Vec::new();
        for e in es {
            let lvl = self.refinable_var(e)?;
            if cols.iter().any(|c: &Col| c.lvl == lvl) {
                return None;
            }
            let ty = e.ty.peel_refs().clone();
            if !matches!(ty, Ty::Bool | Ty::Option(_) | Ty::Adt(..) | Ty::Tuple(_) | Ty::Slice(_) | Ty::Seq(_)) {
                return None;
            }
            let local = match &Elab::peel(e).kind {
                ExprKind::Local(l) => Some(*l),
                _ => None,
            };
            cols.push(Col { lvl, ty, local });
        }
        let mut rows: Vec<Row<'a>> = Vec::new();
        for (i, p) in pats.iter().enumerate() {
            let alts: Vec<&'a Pat> = match &p.kind {
                PatKind::Or(ps) => ps.iter().collect(),
                _ => vec![*p],
            };
            for a in alts {
                let row = match &a.kind {
                    PatKind::Wild => vec![CP::Wild; cols.len()],
                    PatKind::Tuple(ps) if ps.len() == cols.len() && ps.iter().zip(&cols).all(|(q, c)| supported(q, &c.ty, self)) => ps.iter().map(CP::Pat).collect(),
                    _ => return None,
                };
                rows.push(Row { pats: row, arm: i, binds: vec![] });
            }
        }
        let g = Val::new(goal.at(self.depth()), self.depth());
        Some(self.refine_compile(cols, rows, steps, g, kind, span))
    }

    /// The level of a scrutinee that is a (non-let) variable.
    pub fn refinable_var(&self, scrut: &Expr) -> Option<u32> {
        let ExprKind::Local(l) = &Elab::peel(scrut).kind else { return None };
        let lvl = self.f.scope.local(*l)?;
        let e = self.f.scope.ctx.entries.get(lvl as usize)?;
        if e.def.is_some() || e.rel != Rel::Rel {
            return None;
        }
        Some(lvl)
    }

    /// Normalizes column `c` of `row` (derefs, bindings, wildcards).
    fn refine_normalize(&self, row: &mut Row<'a>, c: usize, col: &Col) {
        loop {
            match row.pats[c] {
                CP::Wild => return,
                CP::Pat(p) => match &p.kind {
                    PatKind::Deref { pat, .. } => row.pats[c] = CP::Pat(pat),
                    PatKind::Binding { local, sub, .. } => {
                        row.binds.push((*local, col.lvl));
                        row.pats[c] = match sub {
                            Some(s) => CP::Pat(s),
                            None => CP::Wild,
                        };
                    }
                    PatKind::Wild => row.pats[c] = CP::Wild,
                    PatKind::Slice { prefix, rest, suffix } if suffix.is_empty() => row.pats[c] = CP::Tail { prefix, rest: rest.as_ref().map(|r| r.as_deref()) },
                    _ => return,
                },
                CP::Tail { prefix, rest } => {
                    if !prefix.is_empty() {
                        return;
                    }
                    match rest {
                        None => return,
                        Some(None) => row.pats[c] = CP::Wild,
                        Some(Some(r)) => row.pats[c] = CP::Pat(r),
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn refine_compile(&mut self, cols: Vec<Col>, mut rows: Vec<Row<'a>>, steps: &[&'a [ScriptStmt]], goal: Val, kind: &ObligationKind, span: Span) -> R<Tm> {
        let Some(first) = rows.first_mut() else { return internal(span, "refining match without arms (the front end checks exhaustiveness)") };
        for c in 0..cols.len() {
            let col = cols[c].clone();
            self.refine_normalize(first, c, &col);
        }
        let first = rows[0].clone();
        let Some(c) = first.pats.iter().position(|p| !matches!(p, CP::Wild)) else {
            // the first row matches: bind its locals and run its steps
            let saved = self.f.scope.clone();
            let r = self.refine_bind(&first.binds, 0, span, &mut |s| {
                let g = Val::new(goal.at(s.depth()), s.depth());
                s.branch_script(steps[first.arm], g, kind.clone(), span)
            });
            self.f.scope = saved;
            return r;
        };
        for r in rows.iter_mut().skip(1) {
            let col = cols[c].clone();
            self.refine_normalize(r, c, &col);
        }
        let col = cols[c].clone();
        match &col.ty {
            Ty::Slice(elem) => {
                let elem = (**elem).clone();
                self.refine_slice(cols, rows, c, &elem, steps, goal, kind, span)
            }
            _ => self.refine_ind(cols, rows, c, steps, goal, kind, span),
        }
    }

    fn refine_bind(&mut self, binds: &[(LocalId, u32)], i: usize, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let Some((l, lvl)) = binds.get(i) else { return k(self) };
        self.f.scope.locals.insert(*l, *lvl);
        self.refine_bind(binds, i + 1, span, k)
    }

    /// The facts in scope (not hidden) whose type mentions the variable at
    /// level `x`: `(level, type term at the current depth)`.
    fn dependent_facts(&self, x: u32) -> Vec<(u32, Tm)> {
        let d = self.depth();
        let mut out = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for f in &self.f.scope.facts {
            let l = f.lvl.0;
            if l <= x || self.f.scope.hidden.contains(&l) || !seen.insert(l) {
                continue;
            }
            let Some(t) = self.f.scope.fact_tys.get(&l) else { continue };
            // fact types are recorded at the depth of their binder
            let t = shift(t, (d - l) as i64);
            if mentions(&t, d, x) {
                out.push((l, t));
            }
        }
        out.sort_by_key(|(l, _)| *l);
        out
    }

    /// Pushes the reverted facts, specialized with `x := v` (a term at depth
    /// `vd`), as fact binders; hides the originals. Returns the binder types
    /// (each at the depth where it was pushed).
    fn intro_refined(&mut self, facts: &[(u32, Tm)], d: u32, x: u32, v: &Tm, vd: u32, span: Span) -> R<Vec<Tm>> {
        let mut tys = Vec::new();
        let h0 = self.depth();
        for (j, (l, t)) in facts.iter().enumerate() {
            let here = self.depth();
            let sub = revert_subst(x, v, vd, facts, h0, j);
            let ty = subst_levels(t, d, &sub, here);
            self.push_fact("h_refined", &ty, None, FactOrigin::PathCond, span)?;
            self.f.scope.hidden.insert(*l);
            tys.push(ty);
        }
        Ok(tys)
    }

    /// Development check (`SANDBLASTER_DEBUG_REFINE`): the refined goal is a
    /// well-typed proposition in the arm's context.
    fn debug_check_goal(&self, g: &Tm, what: &str) {
        if std::env::var_os("SANDBLASTER_DEBUG_REFINE").is_none() {
            return;
        }
        let mut b = sandblaster_kernel::value::Budget { steps: 100_000_000 };
        if let Err(e) = self.env.infer(&self.f.scope.ctx, g, &mut b) {
            eprintln!("refine: ill-typed {what}: {}", e.to_string().chars().take(600).collect::<String>());
        }
    }

    /// Rebinds the HIR local of column `col` (if any) to the refined value
    /// `v` (a term at depth `vd`) with a `let`; returns the binder (name,
    /// type, value) for wrapping the arm body.
    fn rebind_local(&mut self, col: &Col, v: &Tm, vd: u32, span: Span) -> R<Option<(String, Tm, Tm)>> {
        let Some(l) = col.local else { return Ok(None) };
        let decl = self.local_decl(l);
        let name = decl.name.clone();
        let ty = self.ty(&decl.ty.clone(), span)?;
        let val = shift(v, (self.depth() - vd) as i64);
        let lvl = self.push(&name, Rel::Rel, &ty, Some(&val))?;
        self.f.scope.locals.insert(l, lvl);
        Ok(Some((name, ty, val)))
    }

    /// Dependent match on an inductive-typed column variable.
    #[allow(clippy::too_many_arguments)]
    fn refine_ind(&mut self, cols: Vec<Col>, rows: Vec<Row<'a>>, c: usize, steps: &[&'a [ScriptStmt]], goal: Val, kind: &ObligationKind, span: Span) -> R<Tm> {
        let col = cols[c].clone();
        let (ind, params) = self.ind_of(&col.ty, span)?;
        let d = self.depth();
        let x = self.f.scope.var(col.lvl);
        let dty = mk::ind(ind, params.clone());
        let facts = self.dependent_facts(col.lvl);
        let g = goal.at(d);
        let er = self.fact_rel();
        // motive at depth d + 1: y at level d, e at d + 1, hᵢ′ at d + 2 + i
        let k = facts.len();
        let mut body = subst_levels(&g, d, &revert_subst(col.lvl, &mk::var(0), d + 1, &facts, d + 2, k), d + 2 + k as u32);
        for (i, (_, t)) in facts.iter().enumerate().rev() {
            let dom = subst_levels(t, d, &revert_subst(col.lvl, &mk::var(0), d + 1, &facts, d + 2, i), d + 2 + i as u32);
            body = mk::pi("h", er, dom, body);
        }
        let motive = mk::pi("e", er, mk::eq(shift(&dty, 1), shift(&x, 1), mk::var(0)), body);
        let decl = self.env.inductive_decl(ind).ok_or_else(|| ElabError { span, msg: "unknown inductive".into(), kind: ErrKind::Internal })?;
        let pvals = params.iter().map(|p| self.eval(p)).collect::<R<Vec<_>>>()?;
        let mut arms = Vec::new();
        for (ci, cdecl) in decl.ctors.iter().enumerate() {
            let saved = self.f.scope.clone();
            let mut fenv: Vec<EnvEntry> = pvals.iter().map(|v| EnvEntry::Rel(v.clone())).collect();
            let mut flvls = Vec::new();
            for (fname, frel, fty) in &cdecl.fields {
                let ftv = self.eval_in(&VEnv(Rc::new(fenv.clone())), fty)?;
                let l = self.push_v(fname, *frel, ftv);
                fenv.push(self.f.scope.venv.0.last().cloned().unwrap());
                flvls.push(l);
            }
            let n = cdecl.fields.len() as u32;
            let dn = d + n;
            let cval = mk::ctor(ind, ci as u32, params.iter().map(|p| shift(p, n as i64)).collect(), (0..n).map(|j| mk::var(n - 1 - j)).collect());
            let eqt = mk::eq(shift(&dty, n as i64), shift(&x, n as i64), cval.clone());
            self.push_fact("e", &eqt, None, FactOrigin::PathCond, span)?;
            let h0 = self.depth();
            let htys = self.intro_refined(&facts, d, col.lvl, &cval, dn, span)?;
            let rebound = self.rebind_local(&col, &cval, dn, span)?;
            let here = self.depth();
            let g2 = subst_levels(&g, d, &revert_subst(col.lvl, &cval, dn, &facts, h0, facts.len()), here);
            self.debug_check_goal(&g2, "inductive arm goal");
            // specialize the rows
            let ftys = self.ctor_field_tys(&col.ty, ci as u32, span)?;
            let mut new_rows = Vec::new();
            for r in &rows {
                let sub: Vec<CP<'a>> = match r.pats[c] {
                    CP::Wild => vec![CP::Wild; n as usize],
                    CP::Pat(p) => match &p.kind {
                        PatKind::Lit(Lit::Bool(b)) => {
                            if u32::from(*b) != ci as u32 {
                                continue;
                            }
                            vec![]
                        }
                        PatKind::Tuple(ps) => ps.iter().map(CP::Pat).collect(),
                        PatKind::Ctor { ctor, fields, .. } => {
                            let idx = match ctor {
                                Ctor::Struct(_) | Ctor::None => 0,
                                Ctor::Some => 1,
                                Ctor::Variant(_, v) => *v,
                            };
                            if idx != ci as u32 {
                                continue;
                            }
                            let mut v = vec![CP::Wild; n as usize];
                            for (fi, fp) in fields {
                                if (*fi as usize) < v.len() {
                                    v[*fi as usize] = CP::Pat(fp);
                                }
                            }
                            v
                        }
                        _ => return internal(span, "unexpected pattern in a refining match"),
                    },
                    // a `Seq` column (the list `Nil` / `Cons(head, tail)`):
                    // `[]` is `Nil`, `[p, ps.., rest @ ..]` is `Cons` with
                    // `p` on the head and the remainder on the tail
                    CP::Tail { prefix, rest } if matches!(col.ty, Ty::Seq(_)) => match (ci, prefix.split_first()) {
                        (0, None) if rest.is_none() => vec![],
                        (0, _) => continue,
                        (_, None) => continue,
                        (_, Some((p0, ps))) => vec![CP::Pat(p0), CP::Tail { prefix: ps, rest }],
                    },
                    CP::Tail { .. } => return internal(span, "slice pattern on an inductive column"),
                };
                let mut pats: Vec<CP<'a>> = r.pats[..c].to_vec();
                pats.extend(sub);
                pats.extend_from_slice(&r.pats[c + 1..]);
                new_rows.push(Row { pats, arm: r.arm, binds: r.binds.clone() });
            }
            let mut new_cols: Vec<Col> = cols[..c].to_vec();
            new_cols.extend(flvls.iter().zip(ftys.iter()).map(|(l, t)| Col { lvl: *l, ty: t.peel_refs().clone(), local: None }));
            new_cols.extend_from_slice(&cols[c + 1..]);
            let body = if new_rows.is_empty() {
                // no row for this constructor: contradictory path
                let empty = mk::ind(self.p.empty, vec![]);
                let p = self.prove(ObligationKind::Unreachable, span, &empty, false)?;
                Ok(Rc::new(Term::Absurd { ty: g2.clone(), proof: p }))
            } else {
                self.refine_compile(new_cols, new_rows, steps, Val::new(g2, here), kind, span)
            };
            self.f.scope = saved;
            let mut b = body?;
            if let Some((name, ty, val)) = rebound {
                b = mk::let_(&name, Rel::Rel, ty, val, b);
            }
            for ty in htys.iter().rev() {
                b = mk::lam("h", er, ty.clone(), b);
            }
            arms.push(Arm { names: cdecl.fields.iter().map(|f| f.0.clone()).collect(), body: mk::lam("e", er, eqt, b) });
        }
        let m = Rc::new(Term::Match { ind, params, scrut: x.clone(), motive, arms });
        let mut t = Rc::new(Term::App { rel: er, fun: m, arg: mk::refl(dty, x) });
        for (l, _) in &facts {
            t = Rc::new(Term::App { rel: er, fun: t, arg: self.f.scope.var(*l) });
        }
        Ok(t)
    }

    /// `slice::cases` on a slice-typed column variable.
    #[allow(clippy::too_many_arguments)]
    fn refine_slice(&mut self, cols: Vec<Col>, rows: Vec<Row<'a>>, c: usize, elem: &Ty, steps: &[&'a [ScriptStmt]], goal: Val, kind: &ObligationKind, span: Span) -> R<Tm> {
        let col = cols[c].clone();
        let lookup = |me: &Self, n: &str| me.env.lookup_global(n).ok_or_else(|| ElabError { span, msg: format!("prelude lemma `{n}` is not loaded"), kind: ErrKind::Internal });
        let cases = lookup(self, "slice::cases")?;
        let empty_g = lookup(self, "slice::empty")?;
        let cons_of = lookup(self, "slice::cons_of")?;
        let d = self.depth();
        let x = self.f.scope.var(col.lvl);
        let et = self.ty(elem, span)?;
        let sty = self.slice_ty(et.clone());
        let facts = self.dependent_facts(col.lvl);
        let g = goal.at(d);
        let er = self.fact_rel();
        // P = λ(s : Slice T). Π(h′ : F[x := s]).. G[x := s]
        // s at level d, hᵢ′ at d + 1 + i
        let k = facts.len();
        let mut pbody = subst_levels(&g, d, &revert_subst(col.lvl, &mk::var(0), d + 1, &facts, d + 1, k), d + 1 + k as u32);
        for (i, (_, t)) in facts.iter().enumerate().rev() {
            let dom = subst_levels(t, d, &revert_subst(col.lvl, &mk::var(0), d + 1, &facts, d + 1, i), d + 1 + i as u32);
            pbody = mk::pi("h", er, dom, pbody);
        }
        let motive = mk::lam("s", Rel::Rel, sty.clone(), pbody);
        // nil: λ(.e : Eq(Slice T, x, empty)) (.hl : fst x = 0). λh′.. body
        let nil = {
            let saved = self.f.scope.clone();
            let empty = mk::app(mk::global(empty_g), et.clone());
            let eqt = mk::eq(sty.clone(), x.clone(), empty.clone());
            self.push("e", Rel::Irr, &eqt, None)?;
            self.note_fact(&eqt, span);
            let hlt = mk::eq(mk::int_ty(Width::Usize), mk::fst(shift(&x, 1)), mk::lit(Width::Usize, 0u8));
            self.push("hl", Rel::Irr, &hlt, None)?;
            self.note_fact(&hlt, span);
            let h0 = self.depth();
            let htys = self.intro_refined(&facts, d, col.lvl, &empty, d, span)?;
            let rebound = self.rebind_local(&col, &empty, d, span)?;
            let here = self.depth();
            let g2 = subst_levels(&g, d, &revert_subst(col.lvl, &empty, d, &facts, h0, facts.len()), here);
            self.debug_check_goal(&g2, "nil arm goal");
            let mut new_rows = Vec::new();
            for r in &rows {
                match r.pats[c] {
                    CP::Wild => {}
                    CP::Tail { prefix, rest: None } if prefix.is_empty() => {}
                    CP::Tail { .. } => continue,
                    CP::Pat(_) => return internal(span, "unexpected pattern on a slice column"),
                }
                let mut pats: Vec<CP<'a>> = r.pats[..c].to_vec();
                pats.extend_from_slice(&r.pats[c + 1..]);
                new_rows.push(Row { pats, arm: r.arm, binds: r.binds.clone() });
            }
            let mut new_cols: Vec<Col> = cols[..c].to_vec();
            new_cols.extend_from_slice(&cols[c + 1..]);
            let body = self.refine_rows_or_absurd(new_cols, new_rows, steps, g2, here, kind, span);
            self.f.scope = saved;
            let mut b = body?;
            if let Some((name, ty, val)) = rebound {
                b = mk::let_(&name, Rel::Rel, ty, val, b);
            }
            for ty in htys.iter().rev() {
                b = mk::lam("h", er, ty.clone(), b);
            }
            mk::lam("e", Rel::Irr, eqt, mk::lam("hl", Rel::Irr, hlt, b))
        };
        // cons: λ(h : T)(t : Slice T)(.hb)(.e : Eq(Slice T, x, h :: t))(.hl). λh′.. body
        let cons = {
            let saved = self.f.scope.clone();
            let etv = self.eval(&et)?;
            let hl_ = self.push_v("h", Rel::Rel, etv);
            let styv = self.eval(&shift(&sty, 1))?;
            let tl_ = self.push_v("t", Rel::Rel, styv);
            let isize_max = mk::global(self.p.g("ISIZE_MAX"));
            let hbt = self.holds(mk::prim(sandblaster_kernel::term::PrimOp::Lt(Width::Int), vec![mk::prim(sandblaster_kernel::term::PrimOp::Cast { from: Width::Usize, to: Width::Int }, vec![mk::fst(mk::var(0))], vec![]), isize_max], vec![]));
            self.push("hb", Rel::Irr, &hbt, None)?;
            self.note_fact(&hbt, span);
            // h :: t at depth d + 3
            let cval = mk::apps(mk::global(cons_of), [(Rel::Rel, shift(&et, 3)), (Rel::Rel, mk::var(2)), (Rel::Rel, mk::var(1)), (Rel::Irr, mk::var(0))]);
            let eqt = mk::eq(shift(&sty, 3), shift(&x, 3), cval.clone());
            self.push("e", Rel::Irr, &eqt, None)?;
            self.note_fact(&eqt, span);
            let cast = |t: Tm| mk::prim(sandblaster_kernel::term::PrimOp::Cast { from: Width::Usize, to: Width::Int }, vec![t], vec![]);
            let hlt = mk::eq(mk::int_ty(Width::Int), cast(mk::fst(shift(&x, 4))), mk::prim(sandblaster_kernel::term::PrimOp::IAdd, vec![mk::lit(Width::Int, 1u8), cast(mk::fst(mk::var(2)))], vec![]));
            self.push("hl", Rel::Irr, &hlt, None)?;
            self.note_fact(&hlt, span);
            let h0 = self.depth();
            let htys = self.intro_refined(&facts, d, col.lvl, &cval, d + 3, span)?;
            let rebound = self.rebind_local(&col, &cval, d + 3, span)?;
            let here = self.depth();
            let g2 = subst_levels(&g, d, &revert_subst(col.lvl, &cval, d + 3, &facts, h0, facts.len()), here);
            self.debug_check_goal(&g2, "cons arm goal");
            let mut new_rows = Vec::new();
            for r in &rows {
                let (hp, tp) = match r.pats[c] {
                    CP::Wild => (CP::Wild, CP::Wild),
                    CP::Tail { prefix, rest } if !prefix.is_empty() => (CP::Pat(&prefix[0]), CP::Tail { prefix: &prefix[1..], rest }),
                    CP::Tail { .. } => continue,
                    CP::Pat(_) => return internal(span, "unexpected pattern on a slice column"),
                };
                let mut pats: Vec<CP<'a>> = r.pats[..c].to_vec();
                pats.push(hp);
                pats.push(tp);
                pats.extend_from_slice(&r.pats[c + 1..]);
                new_rows.push(Row { pats, arm: r.arm, binds: r.binds.clone() });
            }
            let mut new_cols: Vec<Col> = cols[..c].to_vec();
            new_cols.push(Col { lvl: hl_, ty: elem.peel_refs().clone(), local: None });
            new_cols.push(Col { lvl: tl_, ty: Ty::Slice(Box::new(elem.clone())), local: None });
            new_cols.extend_from_slice(&cols[c + 1..]);
            let body = self.refine_rows_or_absurd(new_cols, new_rows, steps, g2, here, kind, span);
            self.f.scope = saved;
            let mut b = body?;
            if let Some((name, ty, val)) = rebound {
                b = mk::let_(&name, Rel::Rel, ty, val, b);
            }
            for ty in htys.iter().rev() {
                b = mk::lam("h", er, ty.clone(), b);
            }
            let b = mk::lam("hl", Rel::Irr, hlt, b);
            let b = mk::lam("e", Rel::Irr, eqt, b);
            let b = mk::lam("hb", Rel::Irr, hbt, b);
            let b = mk::lam("t", Rel::Rel, shift(&sty, 1), b);
            mk::lam("h", Rel::Rel, et.clone(), b)
        };
        let mut t = mk::apps(mk::global(cases), [(Rel::Rel, et), (Rel::Rel, x), (Rel::Rel, motive), (Rel::Rel, nil), (Rel::Rel, cons)]);
        for (l, _) in &facts {
            t = Rc::new(Term::App { rel: er, fun: t, arg: self.f.scope.var(*l) });
        }
        Ok(t)
    }

    #[allow(clippy::too_many_arguments)]
    fn refine_rows_or_absurd(&mut self, cols: Vec<Col>, rows: Vec<Row<'a>>, steps: &[&'a [ScriptStmt]], g: Tm, here: u32, kind: &ObligationKind, span: Span) -> R<Tm> {
        if rows.is_empty() {
            let empty = mk::ind(self.p.empty, vec![]);
            let p = self.prove(ObligationKind::Unreachable, span, &empty, false)?;
            return Ok(Rc::new(Term::Absurd { ty: g, proof: p }));
        }
        self.refine_compile(cols, rows, steps, Val::new(g, here), kind, span)
    }

    /// Records the binder just pushed (the innermost) as a fact.
    fn note_fact(&mut self, ty: &Tm, span: Span) {
        let lvl = self.depth() - 1;
        self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lvl), origin: FactOrigin::PathCond, span });
        self.f.scope.fact_tys.insert(lvl, ty.clone());
    }
}
