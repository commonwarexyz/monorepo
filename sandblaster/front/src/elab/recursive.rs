//! Recursive spec types (§15 S5; SEMANTICS.md §13.9).
//!
//! An enum of a `#[spec]` module may have fields of exactly its own type
//! (`enum Tree { Bytes(Seq<u8>), Cat(Tree, Tree), .. }`); the type checker
//! rejects every other cycle. Such a type is a kernel inductive with direct
//! recursive occurrences (§5.4), and gets two generated definitions:
//!
//! * `T::size' : Π(A..). T(A..) → Int`, its **structural size**: one per
//!   node plus the sizes of the recursive fields, by structural recursion
//!   (`Recursion::Structural`, so the kernel checks termination
//!   syntactically);
//! * `T::size'_pos : Π(A..). Π(t : T(A..)). 1 ≤ size'(t)`, checked, and
//!   used by linear arithmetic for every `size'` atom
//!   (`auto::arith::enrich_bounds`).
//!
//! `size'` is the termination measure of recursion on such a type
//! ([`Elab::size_measure`]): a spec function whose recursive calls pass, at
//! a parameter `p` of the type, variables bound by a pattern on `p`'s
//! recursive fields (also inside a pair `match (p, q)`), and an
//! `#[induction(p)]` proof whose induction hypotheses do the same. The
//! decrease `size'(field) < size'(p)` follows from the path equation of the
//! match (`p = C(.., field, ..)`), the definition of `size'` and
//! `size'_pos`. The name ends in `'`, which no Rust item can, so it never
//! clashes with a method of the type.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use sandblaster_kernel::term::{Arm, DefKind, GlobalId, IndId, PrimOp, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;

use super::exec::Answer;
use super::items::{lam_tele, pi_tele, TBinder};
use super::{internal, Elab, FnState, Mode, RecInfo, Val, R};
use crate::hir::*;
use crate::prover::{FactOrigin, ObligationKind};

/// The suffix of the generated size function's name.
pub const SIZE_SUFFIX: &str = "::size'";

impl<'a> Elab<'a> {
    /// Defines `T::size'` and `T::size'_pos` for the recursive spec type
    /// `id` (declared as `ind`).
    pub fn declare_size(&mut self, id: ItemId, ind: IndId) -> R<()> {
        let krate = self.krate;
        let it = krate.item(id);
        let span = it.span;
        let ItemKind::Enum(e) = &it.kind else { return internal(span, "a recursive type that is not an enum") };
        let ngen = e.generics.len() as u32;
        let name = format!("{}{SIZE_SUFFIX}", it.path);
        // Π(A..). T(A..) → Int
        let mut binders: Vec<TBinder> = e.generics.iter().map(|g| TBinder { name: g.name.clone(), rel: Rel::Rel, ty: mk::ty() }).collect();
        let self_ty = mk::ind(ind, (0..ngen).map(|i| mk::var(ngen - 1 - i)).collect());
        binders.push(TBinder { name: "t".into(), rel: Rel::Rel, ty: self_ty });
        let int = mk::int_ty(Width::Int);
        let fty = pi_tele(&binders, int.clone());
        let d = ngen + 1;
        let params_at = |depth: u32| -> Vec<Tm> { (0..ngen).map(|i| mk::var(depth - 1 - i)).collect() };
        let mut arms = Vec::new();
        for v in &e.variants {
            let n = v.fields.len() as u32;
            let dd = d + n;
            let mut sum = mk::lit(Width::Int, 1u8);
            for (j, f) in v.fields.iter().enumerate() {
                if matches!(&f.ty, Ty::Adt(c, _) if *c == id) {
                    let mut args = params_at(dd);
                    args.push(mk::var(n - 1 - j as u32));
                    let r = Rc::new(Term::Rec { args, proof: None });
                    sum = mk::prim(PrimOp::IAdd, vec![sum, r], vec![]);
                }
            }
            arms.push(Arm { names: (0..n).map(|j| Rc::from(format!("f{j}").as_str())).collect(), body: sum });
        }
        let body = Rc::new(Term::Match { ind, params: params_at(d), scrut: mk::var(0), motive: int.clone(), arms });
        let lam = lam_tele(&binders, body);
        let size = self.add_definition(&name, DefKind::Spec, Some(id), fty, lam, Recursion::Structural { param: ngen }, d, false, false, span)?;
        self.size_pos(id, ind, size, ngen, span)
    }

    /// `T::size'_pos : Π(A..). Π(t : T(A..)). 1 ≤ size'(t)`, by structural
    /// recursion: in each constructor's case the induction hypotheses of
    /// the recursive fields and linear arithmetic close the goal.
    fn size_pos(&mut self, id: ItemId, ind: IndId, size: GlobalId, ngen: u32, span: crate::span::Span) -> R<()> {
        let krate = self.krate;
        let it = krate.item(id);
        let ItemKind::Enum(e) = &it.kind else { return internal(span, "a recursive type that is not an enum") };
        let name = format!("{}{SIZE_SUFFIX}_pos", it.path);
        self.f = FnState::new(name.clone(), Some(id), &[], span);
        self.f.mode = Mode::Proof;
        let mut binders = Vec::new();
        for g in &e.generics {
            self.push(&g.name, Rel::Rel, &mk::ty(), None)?;
            binders.push(TBinder { name: g.name.clone(), rel: Rel::Rel, ty: mk::ty() });
        }
        self.f.ngen = ngen;
        let self_ty = mk::ind(ind, (0..ngen).map(|i| mk::var(ngen - 1 - i)).collect());
        let lt = self.push("t", Rel::Rel, &self_ty, None)?;
        binders.push(TBinder { name: "t".into(), rel: Rel::Rel, ty: self_ty });
        let arity = self.depth();
        // `1 ≤ size'(A.., x)` for a term `x` at depth `depth`
        let goal_of = |me: &Elab<'a>, x: Tm, depth: u32| -> Tm {
            let mut args: Vec<(Rel, Tm)> = (0..ngen).map(|i| (Rel::Rel, mk::var(depth - 1 - i))).collect();
            args.push((Rel::Rel, x));
            me.holds(me.p0(PrimOp::Le(Width::Int), vec![mk::lit(Width::Int, 1u8), mk::apps(mk::global(size), args)]))
        };
        let goal = goal_of(self, self.f.scope.var(lt), arity);
        let lemma_ty = pi_tele(&binders, goal);
        self.f.rec = Some(RecInfo { item: None, ty: lemma_ty.clone(), arity, measure: None });
        let motive = Val::new(goal_of(self, mk::var(0), arity + 1), arity + 1);
        let params: Vec<Tm> = (0..ngen).map(|i| self.f.scope.var(i)).collect();
        let scrut = self.f.scope.var(lt);
        let rec_fields: Vec<Vec<bool>> = e.variants.iter().map(|v| v.fields.iter().map(|f| matches!(&f.ty, Ty::Adt(c, _) if *c == id)).collect()).collect();
        let body = self.dep_match(ind, params, scrut, &Answer::Motive(motive), span, &mut |s, ci, lvls| {
            let recs: Vec<u32> = lvls.iter().zip(&rec_fields[ci as usize]).filter(|(_, r)| **r).map(|(l, _)| *l).collect();
            s.size_ihs(&recs, 0, ngen, &goal_of, span)
        })?;
        let lam = lam_tele(&binders, body);
        let failed = self.f.failed;
        self.add_definition(&name, DefKind::Lemma, Some(id), lemma_ty, lam, Recursion::Structural { param: ngen }, arity, false, failed, span)?;
        Ok(())
    }

    /// Binds the induction hypotheses `1 ≤ size'(f)` of the recursive
    /// fields `recs[i..]` (levels), then proves the branch goal.
    fn size_ihs(&mut self, recs: &[u32], i: usize, ngen: u32, goal_of: &dyn Fn(&Elab<'a>, Tm, u32) -> Tm, span: crate::span::Span) -> R<Tm> {
        let d = self.depth();
        let Some(&l) = recs.get(i) else {
            let g = self.f.branch_goal.clone().map(|g| g.at(d)).ok_or_else(|| super::ElabError { span, msg: "size lemma without a branch goal".into(), kind: super::ErrKind::Internal })?;
            return self.prove(ObligationKind::WellFormed, span, &g, true);
        };
        let x = self.f.scope.var(l);
        let ty = goal_of(self, x.clone(), d);
        let mut args: Vec<Tm> = (0..ngen).map(|k| self.f.scope.var(k)).collect();
        args.push(x);
        let ih = Rc::new(Term::Rec { args, proof: None });
        self.fact_in("ih", ty, ih, FactOrigin::InductionHyp, span, &mut |s| s.size_ihs(recs, i + 1, ngen, goal_of, span))
    }

    /// The global `T::size'` of a recursive spec type, if it was defined.
    pub fn size_global(&self, id: ItemId) -> Option<GlobalId> {
        self.env.lookup_global(&format!("{}{SIZE_SUFFIX}", self.krate.item(id).path))
    }

    /// The termination measure `size'(p)` (a term at the telescope depth)
    /// of a recursion whose calls (argument lists `calls`) pass, at the
    /// position of some parameter `p` of a recursive spec type, a variable
    /// bound to a recursive field of `p` by a pattern of `body`'s matches
    /// ([`field_bindings`]). `params` are the function's parameters and
    /// `ngen` its number of type parameters.
    pub fn size_measure(&self, params: &[Param], ngen: usize, calls: &[&[Expr]], fields_of: &HashMap<LocalId, HashSet<LocalId>>) -> Option<(Tm, Width)> {
        if calls.is_empty() {
            return None;
        }
        for (j, p) in params.iter().enumerate() {
            let PatKind::Binding { local, sub: None, .. } = &p.pat.kind else { continue };
            let Ty::Adt(tid, targs) = p.ty.peel_refs() else { continue };
            if !self.krate.is_recursive_adt(*tid) {
                continue;
            }
            let ok = calls.iter().all(|args| match args.get(j).map(|a| &Elab::peel(a).kind) {
                Some(ExprKind::Local(x)) => fields_of.get(local).is_some_and(|s| s.contains(x)),
                _ => false,
            });
            if !ok {
                continue;
            }
            let size = self.size_global(*tid)?;
            let lvl = ngen as u32 + j as u32;
            let mut args: Vec<(Rel, Tm)> = Vec::new();
            for t in targs {
                args.push((Rel::Rel, self.ty_at(t, lvl, p.span).ok()?));
            }
            args.push((Rel::Rel, self.f.scope.var(lvl)));
            return Some((mk::apps(mk::global(size), args), Width::Int));
        }
        None
    }
}

/// The variables bound to recursive fields of a local by the patterns of
/// matches on it: `match p { C(a, b) => .. }`, `let C(a, b) = p`, and the
/// components of a pair or tuple match `match (p, q) { (C(a, _), D(b)) =>
/// .. }` (transitively: a field of a field is a field). `is_rec(ty)` says
/// whether a pattern's type is a recursive spec type, and only bindings of
/// such fields count (a `Seq` field of a node is not smaller in `size'`).
pub fn field_bindings(pats: &[(Vec<Option<LocalId>>, &Pat)], is_rec: &dyn Fn(&Ty) -> bool) -> HashMap<LocalId, HashSet<LocalId>> {
    let mut out: HashMap<LocalId, HashSet<LocalId>> = HashMap::new();
    fn fields(p: &Pat, is_rec: &dyn Fn(&Ty) -> bool, top: bool, acc: &mut Vec<LocalId>) {
        match &p.kind {
            PatKind::Binding { local, sub, .. } => {
                if !top && is_rec(&p.ty) {
                    acc.push(*local);
                }
                if let Some(s) = sub {
                    fields(s, is_rec, top, acc);
                }
            }
            PatKind::Deref { pat, .. } => fields(pat, is_rec, top, acc),
            PatKind::Or(ps) => ps.iter().for_each(|x| fields(x, is_rec, top, acc)),
            PatKind::Ctor { fields: fs, .. } => fs.iter().for_each(|(_, x)| fields(x, is_rec, false, acc)),
            _ => {}
        }
    }
    for (scruts, pat) in pats {
        // a pair scrutinee: component k of the tuple pattern belongs to
        // scrutinee k
        let comps: Vec<(LocalId, &Pat)> = match (&pat.kind, scruts.len()) {
            (_, 1) => scruts[0].map(|s| vec![(s, *pat)]).unwrap_or_default(),
            (PatKind::Tuple(ps), n) if ps.len() == n => scruts.iter().zip(ps).filter_map(|(s, p)| s.map(|s| (s, p))).collect(),
            (PatKind::Or(alts), _) => {
                let mut v = Vec::new();
                for a in alts {
                    if let PatKind::Tuple(ps) = &a.kind
                        && ps.len() == scruts.len()
                    {
                        v.extend(scruts.iter().zip(ps).filter_map(|(s, p)| s.map(|s| (s, p))));
                    }
                }
                v
            }
            _ => vec![],
        };
        for (s, p) in comps {
            let mut acc = Vec::new();
            fields(p, is_rec, true, &mut acc);
            out.entry(s).or_default().extend(acc);
        }
    }
    // transitivity: a field of a field
    loop {
        let mut changed = false;
        let keys: Vec<LocalId> = out.keys().copied().collect();
        for k in keys {
            let direct: Vec<LocalId> = out[&k].iter().copied().collect();
            for x in direct {
                if let Some(more) = out.get(&x).cloned() {
                    let e = out.get_mut(&k).unwrap();
                    for m in more {
                        changed |= e.insert(m);
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    out
}

/// The scrutinee locals of a match scrutinee: `[x]` for a local, one entry
/// per component for a tuple (`None` where a component is not a local).
pub fn scrut_locals(e: &Expr) -> Vec<Option<LocalId>> {
    let local = |x: &Expr| match &Elab::peel(x).kind {
        ExprKind::Local(l) => Some(*l),
        _ => None,
    };
    match &Elab::peel(e).kind {
        ExprKind::Tuple(es) => es.iter().map(local).collect(),
        _ => vec![local(e)],
    }
}

/// [`field_bindings`] of the matches and `let`s of a function body.
pub fn expr_field_bindings(krate: &Crate, body: &Expr) -> HashMap<LocalId, HashSet<LocalId>> {
    struct V<'x> {
        pats: Vec<(Vec<Option<LocalId>>, &'x Pat)>,
    }
    impl<'x> V<'x> {
        fn go(&mut self, e: &'x Expr) {
            if let ExprKind::Match { scrut, arms, .. } = &e.kind {
                let s = scrut_locals(scrut);
                for a in arms {
                    self.pats.push((s.clone(), &a.pat));
                }
            }
            if let ExprKind::Block(b) = &e.kind {
                for st in &b.stmts {
                    if let StmtKind::Let { pat, init, .. } = &st.kind {
                        self.pats.push((scrut_locals(init), pat));
                    }
                }
            }
            super::items::walk_children_pub(e, &mut |x| self.go(x));
        }
    }
    let mut v = V { pats: vec![] };
    v.go(body);
    field_bindings(&v.pats, &|t| matches!(t.peel_refs(), Ty::Adt(id, _) if krate.is_recursive_adt(*id)))
}

/// [`field_bindings`] of the `match` statements of a proof script (nested
/// ones included).
pub fn script_field_bindings(steps: &[ScriptStmt], is_rec: &dyn Fn(&Ty) -> bool) -> HashMap<LocalId, HashSet<LocalId>> {
    fn go<'x>(steps: &'x [ScriptStmt], out: &mut Vec<(Vec<Option<LocalId>>, &'x Pat)>) {
        for s in steps {
            match &s.kind {
                ScriptKind::Match { scrut, arms } => {
                    let sc = scrut_locals(scrut);
                    for a in arms {
                        out.push((sc.clone(), &a.pat));
                        go(&a.steps, out);
                    }
                }
                ScriptKind::If { then, els, .. } => {
                    go(then, out);
                    go(els, out);
                }
                ScriptKind::Assert { steps: Some(ss), .. } | ScriptKind::Cases { steps: ss, .. } => go(ss, out),
                ScriptKind::Calc { links, .. } => links.iter().filter_map(|l| l.steps.as_ref()).for_each(|ss| go(ss, out)),
                ScriptKind::Let { pat, value } => out.push((scrut_locals(value), pat)),
                _ => {}
            }
        }
    }
    let mut pats = Vec::new();
    go(steps, &mut pats);
    field_bindings(&pats, is_rec)
}
