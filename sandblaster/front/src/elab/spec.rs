//! Spec expressions and propositions (DESIGN.md §4.1).
//!
//! A proposition is a core type (`Prop` ↦ `Type`):
//!
//! | ghost | core |
//! | --- | --- |
//! | `a == b` (proposition position) | `Eq(⟦T⟧, ⟦a⟧, ⟦b⟧)` (operands are expression positions) |
//! | `a != b` | `Not(Eq(..))` |
//! | `p && q` | `Σ(h : ⟦p⟧). ⟦q⟧` — **dependent**: `h` is a fact while elaborating `q` |
//! | `p \|\| q`, `!p` | `Or ⟦p⟧ ⟦q⟧`, `Not ⟦p⟧` |
//! | `implies(p, q)`, `iff(p, q)` | `Π(h : ⟦p⟧). ⟦q⟧` (dependent), `Iff ⟦p⟧ ⟦q⟧` |
//! | `forall(\|x: T\| p)`, `exists(\|x: T\| p)` | `Π(x : ⟦T⟧). ⟦p⟧`, `Exists ⟦T⟧ (λx. ⟦p⟧)` (nested per binder) |
//! | `b` (a `bool`) | `Eq(Bool, ⟦b⟧, true)` |
//! | `if` / `match` / blocks with proposition branches | dependent matches with motive `Type` (large elimination) |
//! | `x as Int`, `Int` arithmetic | exact `Int` primitives (`/`, `%`: Euclidean, divisor ≠ 0 obligation) |
//! | `seq::len(xs)` | `seq::len T (list xs)` |
//! | `seq::index(xs, i)` | `seq::index T (list xs) i` (obligations `0 ≤ i < len`) |
//! | `seq::append/cons/take/drop/update/rev/replicate/empty` | the list operation, rebuilt as a slice (obligation: length `≤ ISIZE_MAX`) |
//! | `eqb(a, b)` | boolean equality at the operands' type |
//!
//! Obligations inside propositions (partial operations, callee `requires`)
//! are proof slots proven in the context of the enclosing binders, so the
//! left conjunct of `&&` is available on the right (`off <= len && len - off
//! >= 64`).

use sandblaster_kernel::term::{PrimOp, Rel, Tm, Width};
use sandblaster_kernel::util::mk;

use super::exec::Answer;
use super::{internal, Elab, ElabError, ErrKind, R};
use crate::builtins::GhostFn;
use crate::hir::*;
use crate::prover::{FactOrigin, ObligationKind};
use crate::span::Span;

impl<'a> Elab<'a> {
    /// `⟦e⟧` for an expression of type `Prop`: a type term at the current
    /// depth. A pure context (`FnState::pure_facts`): the invariant facts
    /// of projected values are hints of its proof slots, never binders of
    /// the type, so the same proposition elaborates to the same type
    /// wherever it is stated (§15.3).
    pub fn prop(&mut self, e: &'a Expr) -> R<Tm> {
        self.in_pure(|s| s.prop_inner(e))
    }

    fn prop_inner(&mut self, e: &'a Expr) -> R<Tm> {
        let span = e.span;
        match &e.kind {
            ExprKind::Coerce(Coercion::BoolToProp, b) => self.expr(b, &mut |s, v| Ok(s.holds(v.at(s.depth())))),
            ExprKind::PropEq(a, b) | ExprKind::PropNe(a, b) => {
                let ne = matches!(e.kind, ExprKind::PropNe(..));
                self.expr(a, &mut |s, va| {
                    s.expr(b, &mut |s, vb| {
                        let d = s.depth();
                        let t = s.ty(&a.ty, span)?;
                        let eq = mk::eq(t, va.at(d), vb.at(d));
                        Ok(if ne { mk::app(mk::global(s.p.g("Not")), eq) } else { eq })
                    })
                })
            }
            ExprKind::PropAnd(p, q) | ExprKind::Implies(p, q) => {
                let and = matches!(e.kind, ExprKind::PropAnd(..));
                let pt = self.prop(p)?;
                let saved = self.f.scope.clone();
                let lvl = self.push("h", Rel::Rel, &pt, None)?;
                self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lvl), origin: FactOrigin::Assert, span: p.span });
                self.f.scope.fact_tys.insert(lvl, pt.clone());
                let qt = self.prop(q);
                self.f.scope = saved;
                let qt = qt?;
                Ok(if and { mk::sigma("h", Rel::Rel, pt, qt) } else { mk::pi("h", Rel::Rel, pt, qt) })
            }
            ExprKind::PropOr(p, q) | ExprKind::Iff(p, q) => {
                let g = if matches!(e.kind, ExprKind::PropOr(..)) { "Or" } else { "Iff" };
                let pt = self.prop(p)?;
                let qt = self.prop(q)?;
                Ok(mk::apps(mk::global(self.p.g(g)), [(Rel::Rel, pt), (Rel::Rel, qt)]))
            }
            ExprKind::PropNot(p) => {
                let pt = self.prop(p)?;
                Ok(mk::app(mk::global(self.p.g("Not")), pt))
            }
            ExprKind::Quant { quant, binders, body } => self.quant(*quant, binders, body, span),
            ExprKind::If { cond, then, els } => self.expr(cond, &mut |s, vc| {
                let c = vc.at(s.depth());
                s.if_then_else(c, &Answer::Prop, span, &mut |s, b| match (b, els) {
                    (true, _) => s.prop(then),
                    (false, Some(x)) => s.prop(x),
                    (false, None) => Ok(mk::ind(s.p.unit, vec![])),
                })
            }),
            ExprKind::Match { scrut, arms, .. } => self.prop_match(scrut, arms, span),
            ExprKind::Block(b) => self.block(b, &mut |s, v| Ok(v.at(s.depth()))),
            // any other Prop-typed expression (a call of a `-> Prop` spec fn)
            _ => self.expr_value(e, &mut |s, v| Ok(v.at(s.depth()))),
        }
    }

    fn quant(&mut self, q: Quant, binders: &'a [LocalId], body: &'a Expr, span: Span) -> R<Tm> {
        let Some((first, rest)) = binders.split_first() else { return self.prop(body) };
        let decl = self.local_decl(*first);
        let t = self.ty(&decl.ty, span)?;
        let name = decl.name.clone();
        let saved = self.f.scope.clone();
        let lvl = self.push(&name, Rel::Rel, &t, None)?;
        self.f.scope.locals.insert(*first, lvl);
        // a `Nat` binder carries its bound (§4.1): `∀n. 0 ≤ n → p`,
        // `∃n. 0 ≤ n ∧ p`; so do the `Nat` components of a binder (fields
        // of spec structs, tuple components; S2) and the `Nat`s inside its
        // sequences, arrays, options and enums (their well-formedness,
        // [`Elab::nat_bounds`]): the kernel quantifies over exactly the
        // values the source type allows, in every position
        let comps = self.nat_bounds(&decl.ty, self.f.scope.var(lvl), true, span)?;
        let mut bounds = Vec::new();
        let d0 = self.depth();
        for c in comps {
            let b = sandblaster_kernel::util::shift(&c, (self.depth() - d0) as i64);
            let hl = self.push("h_nat", Rel::Rel, &b, None)?;
            self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(hl), origin: FactOrigin::TypeBound, span });
            self.f.scope.fact_tys.insert(hl, b.clone());
            bounds.push(b);
        }
        let inner = self.quant(q, rest, body, span);
        self.f.scope = saved;
        let mut inner = inner?;
        for b in bounds.into_iter().rev() {
            inner = match q {
                Quant::Forall => mk::pi("h_nat", Rel::Rel, b, inner),
                Quant::Exists => mk::sigma("h_nat", Rel::Rel, b, inner),
            };
        }
        Ok(match q {
            Quant::Forall => mk::pi(&name, Rel::Rel, t, inner),
            Quant::Exists => mk::apps(mk::global(self.p.g("Exists")), [(Rel::Rel, t.clone()), (Rel::Rel, mk::lam(&name, Rel::Rel, t, inner))]),
        })
    }

    /// A proposition-valued match: CPS with motive `Type`.
    fn prop_match(&mut self, scrut: &'a Expr, arms: &'a [Arm], span: Span) -> R<Tm> {
        let expanded: &'a [Arm] = self.expanded_arms(arms);
        self.expr(scrut, &mut |s, v| s.match_on(v, &scrut.ty, expanded, &Answer::Prop, span, &mut |s, i| s.prop(&expanded[i].body)))
    }

    // ------------------------------------------------------------------
    // ghost functions
    // ------------------------------------------------------------------

    /// The list inside a slice value.
    fn list_of(&self, s: Tm) -> Tm {
        mk::fst(mk::snd(s))
    }

    /// A slice rebuilt from a list, with its length bound as an obligation
    /// (§4.1: operations that build a slice require the `ISIZE_MAX` bound).
    pub fn slice_of_list(&mut self, et: Tm, l: Tm, span: Span) -> R<Tm> {
        let len = mk::apps(mk::global(self.p.g("seq::len")), [(Rel::Rel, et.clone()), (Rel::Rel, l.clone())]);
        let int = Width::Int;
        let le = |a: Tm, b: Tm| mk::prim(PrimOp::Le(int), vec![a, b], vec![]);
        let bound = self.holds(le(len.clone(), mk::global(self.p.g("ISIZE_MAX"))));
        let pb = self.prove(ObligationKind::WellFormed, span, &bound, false)?;
        let g0 = self.holds(le(mk::lit(int, 0u8), len.clone()));
        let p0 = self.prove(ObligationKind::WellFormed, span, &g0, false)?;
        let g1 = self.holds(le(len.clone(), mk::lit(int, sandblaster_kernel::prim::max_of(Width::Usize))));
        let p1 = self.prove(ObligationKind::WellFormed, span, &g1, false)?;
        let n = mk::prim(PrimOp::OfInt(Width::Usize), vec![len.clone()], vec![p0, p1]);
        let cast_n = mk::prim(PrimOp::Cast { from: Width::Usize, to: int }, vec![n.clone()], vec![]);
        let geq = mk::eq(mk::int_ty(int), len.clone(), cast_n.clone());
        let peq = self.prove(ObligationKind::WellFormed, span, &geq, false)?;
        let gb = self.holds(le(cast_n, mk::global(self.p.g("ISIZE_MAX"))));
        let pb2 = if matches!(&*pb, sandblaster_kernel::term::Term::Erased) { pb } else { self.prove(ObligationKind::WellFormed, span, &gb, false)? };
        let ok_ty = mk::apps(mk::global(self.p.g("SliceOk")), [(Rel::Rel, et.clone()), (Rel::Rel, n.clone()), (Rel::Rel, l.clone())]);
        let ok = mk::pair(ok_ty, peq, pb2);
        Ok(mk::apps(mk::global(self.p.g("slice::mk")), [(Rel::Rel, et), (Rel::Rel, n), (Rel::Rel, l), (Rel::Irr, ok)]))
    }

    /// Calls of the ghost prelude functions.
    pub fn ghost_call(&mut self, g: GhostFn, targs: &[Ty], args: Vec<Tm>, span: Span) -> R<Tm> {
        if let Some(t) = self.ghost_call_s1(g, targs, &args, span)? {
            return Ok(t);
        }
        let elem = targs.first().cloned().ok_or_else(|| ElabError { span, msg: "ghost function without type argument".into(), kind: ErrKind::Internal })?;
        let et = self.ty(&elem, span)?;
        let a = |i: usize| args.get(i).cloned().ok_or_else(|| ElabError { span, msg: "ghost function arity".into(), kind: ErrKind::Internal });
        let seq = |me: &Self, n: &str, xs: Vec<Tm>| mk::apps(mk::global(me.p.g(n)), xs.into_iter().map(|x| (Rel::Rel, x)));
        Ok(match g {
            GhostFn::SeqLen => seq(self, "seq::len", vec![et, self.list_of(a(0)?)]),
            GhostFn::SeqIndex => {
                let l = self.list_of(a(0)?);
                let i = a(1)?;
                let len = seq(self, "seq::len", vec![et.clone(), l.clone()]);
                let g0 = self.holds(mk::prim(PrimOp::Le(Width::Int), vec![mk::lit(Width::Int, 0u8), i.clone()], vec![]));
                let p0 = self.prove(ObligationKind::IndexBounds, span, &g0, false)?;
                let g1 = self.holds(mk::prim(PrimOp::Lt(Width::Int), vec![i.clone(), len], vec![]));
                let p1 = self.prove(ObligationKind::IndexBounds, span, &g1, false)?;
                mk::apps(mk::global(self.p.g("seq::index")), [(Rel::Rel, et), (Rel::Rel, l), (Rel::Rel, i), (Rel::Irr, p0), (Rel::Irr, p1)])
            }
            GhostFn::SeqAppend => {
                let l = seq(self, "seq::append", vec![et.clone(), self.list_of(a(0)?), self.list_of(a(1)?)]);
                self.slice_of_list(et, l, span)?
            }
            GhostFn::SeqCons => {
                let l = mk::ctor(self.p.list, 1, vec![et.clone()], vec![a(0)?, self.list_of(a(1)?)]);
                self.slice_of_list(et, l, span)?
            }
            GhostFn::SeqTake | GhostFn::SeqDrop => {
                let n = if g == GhostFn::SeqTake { "seq::take" } else { "seq::drop" };
                let l = seq(self, n, vec![et.clone(), self.list_of(a(0)?), a(1)?]);
                self.slice_of_list(et, l, span)?
            }
            GhostFn::SeqUpdate => {
                let l = seq(self, "seq::update", vec![et.clone(), self.list_of(a(0)?), a(1)?, a(2)?]);
                self.slice_of_list(et, l, span)?
            }
            GhostFn::SeqRev => {
                let l = seq(self, "seq::rev", vec![et.clone(), self.list_of(a(0)?)]);
                self.slice_of_list(et, l, span)?
            }
            GhostFn::SeqReplicate => {
                let l = seq(self, "seq::replicate", vec![et.clone(), a(0)?, a(1)?]);
                self.slice_of_list(et, l, span)?
            }
            GhostFn::SeqEmpty => {
                let l = mk::ctor(self.p.list, 0, vec![et.clone()], vec![]);
                self.slice_of_list(et, l, span)?
            }
            GhostFn::Eqb => {
                let (x, y) = (a(0)?, a(1)?);
                match elem.peel_refs() {
                    Ty::Uint(w) => mk::prim(PrimOp::Eq(w.width()), vec![x, y], vec![]),
                    Ty::Int | Ty::Nat => mk::prim(PrimOp::Eq(Width::Int), vec![x, y], vec![]),
                    Ty::Bool => mk::apps(mk::global(self.p.g("bool::eq")), [(Rel::Rel, x), (Rel::Rel, y)]),
                    other => {
                        let o = other.clone();
                        self.struct_eq(&o, &o, x, y, span)?
                    }
                }
            }
            _ => return internal(span, format!("ghost function `{}` reached the slice case", g.name())),
        })
    }

    /// The §4.1 `Seq<T>`, `Nat` and `Int` operations of S1 (`None`: a
    /// slice-based `seq::*` function or `eqb`).
    fn ghost_call_s1(&mut self, g: GhostFn, targs: &[Ty], args: &[Tm], span: Span) -> R<Option<Tm>> {
        use GhostFn::*;
        let a = |i: usize| args.get(i).cloned().ok_or_else(|| ElabError { span, msg: format!("`{}`: arity", g.name()), kind: ErrKind::Internal });
        let int = Width::Int;
        let elem = || -> R<Tm> {
            match targs.first() {
                Some(t) => self.ty(t, span),
                None => internal(span, format!("`{}` without its type argument", g.name())),
            }
        };
        let app = |me: &Self, n: &str, xs: Vec<Tm>| mk::apps(mk::global(me.p.g(n)), xs.into_iter().map(|x| (Rel::Rel, x)));
        let lib = |me: &Self, n: &str| -> R<Tm> {
            me.env.lookup_global(n).map(mk::global).ok_or_else(|| ElabError { span, msg: format!("ghost library definition `{n}` is missing"), kind: ErrKind::Internal })
        };
        let t = match g {
            SLen => app(self, "seq::len", vec![elem()?, a(0)?]),
            SGet => mk::apps(lib(self, "ghost::seq_get")?, [(Rel::Rel, elem()?), (Rel::Rel, a(0)?), (Rel::Rel, a(1)?)]),
            SIndex => {
                let (et, l, i) = (elem()?, a(0)?, a(1)?);
                let len = app(self, "seq::len", vec![et.clone(), l.clone()]);
                let g0 = self.holds(mk::prim(PrimOp::Le(int), vec![mk::lit(int, 0u8), i.clone()], vec![]));
                let p0 = self.prove(ObligationKind::IndexBounds, span, &g0, false)?;
                let g1 = self.holds(mk::prim(PrimOp::Lt(int), vec![i.clone(), len], vec![]));
                let p1 = self.prove(ObligationKind::IndexBounds, span, &g1, false)?;
                mk::apps(mk::global(self.p.g("seq::index")), [(Rel::Rel, et), (Rel::Rel, l), (Rel::Rel, i), (Rel::Irr, p0), (Rel::Irr, p1)])
            }
            STake => app(self, "seq::take", vec![elem()?, a(0)?, a(1)?]),
            SSkip => app(self, "seq::drop", vec![elem()?, a(0)?, a(1)?]),
            SChunks(n) => {
                let et = elem()?;
                let hn = mk::refl(mk::bool_ty(self.p.bool_), self.bool_lit(true));
                let chunks = self.env.lookup_global("seq::chunks").ok_or_else(|| ElabError { span, msg: "prelude `seq::chunks` is missing".into(), kind: ErrKind::Internal })?;
                mk::apps(mk::global(chunks), [(Rel::Rel, et), (Rel::Rel, mk::lit(Width::Usize, n)), (Rel::Irr, hn), (Rel::Rel, a(0)?)])
            }
            SFlatten(Some(n)) => mk::apps(lib(self, "ghost::arrays_flatten")?, [(Rel::Rel, elem()?), (Rel::Rel, mk::lit(Width::Usize, n)), (Rel::Rel, a(0)?)]),
            SFlatten(None) => mk::apps(lib(self, "ghost::seq_flatten")?, [(Rel::Rel, elem()?), (Rel::Rel, a(0)?)]),
            SToArray(n) => {
                let (et, l) = (elem()?, a(0)?);
                let len = app(self, "seq::len", vec![et.clone(), l.clone()]);
                let goal = mk::eq(mk::int_ty(int), len, mk::lit(int, n));
                let pf = self.prove(ObligationKind::WellFormed, span, &goal, false)?;
                mk::pair(self.array_ty(et, n), l, pf)
            }
            SRepeat => app(self, "seq::replicate", vec![elem()?, a(1)?, a(0)?]),
            SEmpty => mk::ctor(self.p.list, 0, vec![elem()?], vec![]),
            SCons => mk::ctor(self.p.list, 1, vec![elem()?], vec![a(0)?, a(1)?]),
            SAppend => app(self, "seq::append", vec![elem()?, a(0)?, a(1)?]),
            SUpdate => app(self, "seq::update", vec![elem()?, a(0)?, a(1)?, a(2)?]),
            SRev => app(self, "seq::rev", vec![elem()?, a(0)?]),
            NMin | NMax => {
                // `if a <= b { a } else { b }` (min), `{ b } else { a }` (max)
                let (x, y) = (a(0)?, a(1)?);
                let c = mk::prim(PrimOp::Le(int), vec![x.clone(), y.clone()], vec![]);
                let (t_arm, f_arm) = if g == NMin { (x, y) } else { (y, x) };
                self.bool_ite(c, mk::int_ty(int), t_arm, f_arm)
            }
            NSatSub => {
                let (x, y) = (a(0)?, a(1)?);
                let c = mk::prim(PrimOp::Le(int), vec![y.clone(), x.clone()], vec![]);
                let d = mk::prim(PrimOp::ISub, vec![x, y], vec![]);
                self.bool_ite(c, mk::int_ty(int), d, mk::lit(int, 0u8))
            }
            Pow2 | Log2 | Popcount => {
                let n = g.nat_def().unwrap_or_default();
                mk::app(lib(self, n)?, a(0)?)
            }
            IDivEuclid | IRemEuclid => {
                let (x, y) = (a(0)?, a(1)?);
                let nz = self.holds(mk::prim(PrimOp::Ne(int), vec![y.clone(), mk::lit(int, 0u8)], vec![]));
                let pf = self.prove(ObligationKind::DivZero, span, &nz, false)?;
                let op = if g == IDivEuclid { PrimOp::IDiv } else { PrimOp::IMod };
                mk::let_("h_div", Rel::Irr, nz, pf, mk::prim(op, vec![sandblaster_kernel::util::shift(&x, 1), sandblaster_kernel::util::shift(&y, 1)], vec![]))
            }
            _ => return Ok(None),
        };
        Ok(Some(t))
    }

    /// `match c : Bool as _ return T with | false => f | true => t end`
    /// (closed branches: they do not mention the scrutinee).
    pub fn bool_ite(&self, c: Tm, ty: Tm, t: Tm, f: Tm) -> Tm {
        std::rc::Rc::new(sandblaster_kernel::term::Term::Match {
            ind: self.p.bool_,
            params: vec![],
            scrut: c,
            motive: sandblaster_kernel::util::shift(&ty, 1),
            arms: vec![sandblaster_kernel::term::Arm { names: vec![], body: f }, sandblaster_kernel::term::Arm { names: vec![], body: t }],
        })
    }

    /// Non-proposition dispatch of [`Elab::expr`] (for `Prop`-typed calls).
    pub fn expr_value(&mut self, e: &'a Expr, k: &mut super::exec::K<'_, 'a>) -> R<Tm> {
        match &e.kind {
            ExprKind::Call { callee, args } => self.exprs(args, &mut |s, vs| {
                let d = s.depth();
                let args: Vec<Tm> = vs.iter().map(|v| v.at(d)).collect();
                let t = match callee {
                    Callee::Item(id, targs) => s.item_call(*id, targs, args, e.span)?,
                    Callee::Ghost(g, targs) => s.ghost_call(*g, targs, args, e.span)?,
                    _ => return internal(e.span, "proposition-valued call of a non-spec function"),
                };
                s.cont(k, t)
            }),
            _ => internal(e.span, "unsupported proposition form"),
        }
    }
}
