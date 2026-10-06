//! Exec expressions and statements (DESIGN.md §3.3, §3.5, §7.3).
//!
//! Elaboration is in **continuation-passing style**: [`Elab::expr`] takes a
//! continuation `k` that receives the value of the expression (a term at
//! the depth where it is produced) and returns the term of the whole rest of
//! the computation. Sequential constructs bind nothing unless they must
//! (statements become `let`s, assignments new SSA `let`s); branching
//! constructs are elaborated in one of two ways:
//!
//! * **join** (no `return`/`?` inside): each branch ends in the *join
//!   value* — the branch value, tupled with the current versions of the
//!   outer locals the construct assigns (SSA joins, §7.3) — the dependent
//!   match is bound by `let j = ..`, destructured, and `k` is called once;
//! * **CPS** (a `return` or `?` inside; also, up to [`CPS_LIMIT`] nested
//!   duplications, a construct that assigns outer locals): `k` is pushed
//!   into every branch (early exits simply do not call it), so "the rest of
//!   the block moves into the non-returning branch" (§7.3), and code after
//!   an assigning `if`/`match` sees each branch's values under that
//!   branch's path condition.
//!
//! Both shapes denote the same function (the continuation is pure); which
//! one is used is part of the normative elaboration (SEMANTICS.md §6).
//!
//! `if`, `&&`, `||` and `?` use the dependent-match idiom of §7.2
//! (`match c as y return Π(e :Irr Eq(D, c, y)). A with ..` applied to
//! `refl`), so every branch has its path condition as a fact.
//! `unreachable!()` is `absurd(A, p)` with an `Unreachable` obligation.

use std::collections::BTreeSet;
use std::rc::Rc;

use sandblaster_kernel::term::{Arm, IndId, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::{mk, shift};
use sandblaster_kernel::value::{EnvEntry, VEnv};

use super::{internal, unsupported, Elab, ElabError, ErrKind, Val, R};
use crate::builtins::{ArrayMethod, Builtin, IntMethod, OptionMethod, SliceMethod};
use crate::hir::*;
use crate::prover::{FactOrigin, ObligationKind};
use crate::span::Span;
use crate::visit::{self, Visitor};

/// A continuation: receives a value, returns the rest of the computation.
pub type K<'k, 'a> = dyn FnMut(&mut Elab<'a>, Val) -> R<Tm> + 'k;

/// The answer type of a dependent match.
#[derive(Clone, Debug)]
pub enum Answer {
    /// A HIR type (translated at each depth).
    Ty(Ty),
    /// `Type` (propositions, large elimination).
    Prop,
    /// A type term built at some depth.
    Tm(Val),
    /// A motive: a type term at depth `d + 1` whose `Var(0)` is the
    /// scrutinee of the dependent match at depth `d` (script refinement,
    /// §4.4). Each arm's goal is the motive at its constructor
    /// (`FnState::branch_goal`).
    Motive(Val),
}

/// Maximum nesting of continuation duplication for assigning branches
/// (beyond it, SSA joins are used).
pub const CPS_LIMIT: u32 = 8;

/// Whether an expression contains `return` or `?`.
pub fn has_exit(e: &Expr) -> bool {
    struct V(bool);
    impl Visitor for V {
        fn expr(&mut self, e: &Expr) {
            if matches!(e.kind, ExprKind::Return(_) | ExprKind::Try(_)) {
                self.0 = true;
            }
            if !self.0 {
                visit::walk_expr(self, e);
            }
        }
    }
    let mut v = V(false);
    v.expr(e);
    v.0
}

/// Locals assigned (by assignment, compound assignment, `copy_from_slice`
/// or inside a loop) somewhere in `e`, sorted by id.
pub fn assigned_in(e: &Expr) -> BTreeSet<LocalId> {
    struct V(BTreeSet<LocalId>);
    impl Visitor for V {
        fn place(&mut self, p: &Place) {
            self.0.insert(p.local);
            visit::walk_place(self, p);
        }
        fn stmt(&mut self, s: &Stmt) {
            if let StmtKind::CopyFromSlice { dst, .. } = &s.kind {
                self.0.insert(*dst);
            }
            visit::walk_stmt(self, s);
        }
        fn loop_(&mut self, l: &Loop) {
            self.0.extend(l.info.mutated.iter().copied());
            visit::walk_loop(self, l);
        }
    }
    let mut v = V(BTreeSet::new());
    v.expr(e);
    v.0
}

/// The length from which a chain of one short-circuit operator is
/// elaborated right-nested ([`Elab::short_circuit`]).
const FLAT_CHAIN: usize = 5;

/// The operands of a chain of `&&` (`and`) or `||` (whatever its
/// nesting), left to right.
fn chain_operands<'x>(e: &'x Expr, and: bool, out: &mut Vec<&'x Expr>) {
    match &e.kind {
        ExprKind::Binary(op @ (BinOp::And | BinOp::Or), a, b) if (*op == BinOp::And) == and => {
            chain_operands(a, and, out);
            chain_operands(b, and, out);
        }
        _ => out.push(e),
    }
}

fn peel_coerce(e: &Expr) -> &Expr {
    match &e.kind {
        ExprKind::Coerce(Coercion::AutoDeref | Coercion::AutoRef, x) | ExprKind::Ref(x) | ExprKind::Deref(x) => peel_coerce(x),
        _ => e,
    }
}

impl<'a> Elab<'a> {
    /// Calls a continuation with a term at the current depth.
    pub fn cont(&mut self, k: &mut K<'_, 'a>, t: Tm) -> R<Tm> {
        let v = Val::new(t, self.depth());
        k(self, v)
    }

    /// The answer type as a term at the current depth.
    pub fn answer_tm(&self, a: &Answer, span: Span) -> R<Tm> {
        match a {
            Answer::Ty(t) => self.ty(t, span),
            Answer::Prop => Ok(mk::ty()),
            Answer::Tm(v) => Ok(v.at(self.depth())),
            Answer::Motive(_) => match &self.f.branch_goal {
                Some(g) => Ok(g.at(self.depth())),
                None => internal(span, "motive answer outside its match"),
            },
        }
    }

    // ------------------------------------------------------------------
    // expressions
    // ------------------------------------------------------------------

    /// Elaborates `e` and passes its value to `k` (see the module docs).
    pub fn expr(&mut self, e: &'a Expr, k: &mut K<'_, 'a>) -> R<Tm> {
        let span = e.span;
        if e.ty == Ty::Prop
            && matches!(
                e.kind,
                ExprKind::Coerce(Coercion::BoolToProp, _) | ExprKind::PropEq(..) | ExprKind::PropNe(..) | ExprKind::PropAnd(..) | ExprKind::PropOr(..) | ExprKind::PropNot(_) | ExprKind::Implies(..) | ExprKind::Iff(..) | ExprKind::Quant { .. } | ExprKind::If { .. } | ExprKind::Match { .. }
            )
        {
            let p = self.prop(e)?;
            return self.cont(k, p);
        }
        match &e.kind {
            ExprKind::Lit(l) => {
                let t = self.lit_tm(l, &e.ty, span)?;
                self.cont(k, t)
            }
            ExprKind::Local(l) => {
                let t = self.local_tm(*l, span)?;
                self.cont(k, t)
            }
            ExprKind::Const(id) => {
                let g = self.item_global(*id, span)?;
                self.cont(k, mk::global(g))
            }
            ExprKind::BuiltinConst(c) => {
                let t = match c {
                    BuiltinConst::Max(w) => mk::lit(w.width(), w.max_value()),
                    BuiltinConst::Min(w) => mk::lit(w.width(), 0u8),
                    BuiltinConst::Bits(w) => mk::lit(Width::U32, w.bits()),
                    BuiltinConst::IsizeMax => mk::global(self.p.g("ISIZE_MAX")),
                };
                self.cont(k, t)
            }
            ExprKind::Call { callee, args } => self.exprs(args, &mut |s, vs| s.call(e, callee, vs, k)),
            ExprKind::Adt { ctor, ty_args, fields, base } => {
                let exprs: Vec<&'a Expr> = fields.iter().map(|(_, x)| x).chain(base.iter().map(|b| &**b)).collect();
                self.exprs_ref(&exprs, &mut |s, vs| {
                    let t = s.adt_value(e, *ctor, ty_args, fields, base.is_some(), vs)?;
                    s.cont(k, t)
                })
            }
            ExprKind::Tuple(es) => self.exprs(es, &mut |s, vs| {
                let d = s.depth();
                let tys = es.iter().map(|x| s.ty(&x.ty, span)).collect::<R<Vec<_>>>()?;
                let t = s.tuple_val(tys, vs.iter().map(|v| v.at(d)).collect(), span)?;
                s.cont(k, t)
            }),
            ExprKind::Array(es) => self.exprs(es, &mut |s, vs| {
                let d = s.depth();
                let Ty::Array(elem, n) = &e.ty else { return internal(span, "array literal of non-array type") };
                let et = s.ty(elem, span)?;
                let mut list = mk::ctor(s.p.list, 0, vec![et.clone()], vec![]);
                for v in vs.iter().rev() {
                    list = mk::ctor(s.p.list, 1, vec![et.clone()], vec![v.at(d), list]);
                }
                let t = mk::pair(s.array_ty(et, *n), list, mk::refl(mk::int_ty(Width::Int), mk::lit(Width::Int, *n)));
                s.cont(k, t)
            }),
            ExprKind::Repeat { elem, count } => self.expr(elem, &mut |s, v| {
                let et = s.ty(&elem.ty, span)?;
                let t = mk::apps(
                    mk::global(s.p.g("array::repeat")),
                    [(Rel::Rel, et), (Rel::Rel, mk::lit(Width::Usize, *count)), (Rel::Rel, v.at(s.depth())), (Rel::Irr, mk::refl(mk::int_ty(Width::Int), mk::lit(Width::Int, *count)))],
                );
                s.cont(k, t)
            }),
            ExprKind::Field { base, index, .. } => self.expr(base, &mut |s, v| {
                // a projection of a value with an invariant: its facts (§15.3)
                s.with_inv_facts(&v, &base.ty, span, &mut |s| {
                    let t = s.field(&base.ty, v.at(s.depth()), *index as usize, span)?;
                    s.cont(k, t)
                })
            }),
            ExprKind::Index { base, index } => self.expr(base, &mut |s, vb| {
                s.expr(index, &mut |s, vi| {
                    let d = s.depth();
                    let t = s.index(&base.ty, vb.at(d), vi.at(d), span)?;
                    s.cont(k, t)
                })
            }),
            ExprKind::SliceRange { base, lo, hi } => {
                let mut list: Vec<&'a Expr> = vec![&**base];
                list.extend(lo.iter().map(|x| &**x));
                list.extend(hi.iter().map(|x| &**x));
                self.exprs_ref(&list, &mut |s, vs| {
                    let d = s.depth();
                    let b = vs[0].at(d);
                    let lo_t = lo.as_ref().map(|_| vs[1].at(d));
                    let hi_t = hi.as_ref().map(|_| vs[if lo.is_some() { 2 } else { 1 }].at(d));
                    let t = s.slice_range(&base.ty, b, lo_t, hi_t, span)?;
                    s.cont(k, t)
                })
            }
            ExprKind::Unary(op, x) => self.expr(x, &mut |s, v| {
                let t = s.unary(*op, &x.ty, v.at(s.depth()), span)?;
                s.cont(k, t)
            }),
            ExprKind::Binary(BinOp::And, a, b) => self.short_circuit(e, a, b, true, k),
            ExprKind::Binary(BinOp::Or, a, b) => self.short_circuit(e, a, b, false, k),
            ExprKind::Binary(op, a, b) => self.expr(a, &mut |s, va| {
                s.expr(b, &mut |s, vb| {
                    let d = s.depth();
                    let t = s.binop(*op, &a.ty, &b.ty, va.at(d), vb.at(d), span)?;
                    s.cont(k, t)
                })
            }),
            ExprKind::Cast(x, to) => self.expr(x, &mut |s, v| {
                let t = s.cast(&x.ty, to, v.at(s.depth()), span)?;
                s.cont(k, t)
            }),
            ExprKind::Ref(x) | ExprKind::Deref(x) => self.expr(x, k),
            ExprKind::Coerce(c, x) => match c {
                Coercion::AutoRef | Coercion::AutoDeref => self.expr(x, k),
                Coercion::Unsize => self.expr(x, &mut |s, v| {
                    let t = s.unsize(&x.ty, v.at(s.depth()), span)?;
                    s.cont(k, t)
                }),
                Coercion::BoolToProp => self.expr(x, &mut |s, v| {
                    let t = s.holds(v.at(s.depth()));
                    s.cont(k, t)
                }),
                Coercion::View => self.expr(x, &mut |s, v| {
                    let t = s.abstraction(&x.ty, &e.ty, v.at(s.depth()), span)?;
                    s.cont(k, t)
                }),
            },
            ExprKind::If { cond, then, els } => self.if_expr(e, cond, then, els.as_deref(), k),
            ExprKind::Match { scrut, arms, .. } => self.match_expr(e, scrut, arms, k),
            ExprKind::Block(b) => self.block(b, k),
            ExprKind::Return(x) => match x {
                Some(x) => self.expr(x, &mut |s, v| Ok(v.at(s.depth()))),
                None => Ok(self.unit_val()),
            },
            ExprKind::Try(x) => self.expr(x, &mut |s, v| s.try_(x, v, k, span)),
            ExprKind::Unreachable => self.unreachable(span),
            ExprKind::Loop(l) => self.loop_(l, k),
            ExprKind::PropEq(..) | ExprKind::PropNe(..) | ExprKind::PropAnd(..) | ExprKind::PropOr(..) | ExprKind::PropNot(_) | ExprKind::Implies(..) | ExprKind::Iff(..) | ExprKind::Quant { .. } => {
                let p = self.prop(e)?;
                self.cont(k, p)
            }
            ExprKind::Lambda { params, body } => {
                let t = self.lambda(params, body, span)?;
                self.cont(k, t)
            }
            // `f(a, b)`: the curried application `f a b`
            ExprKind::Apply { fun, args } => self.expr(fun, &mut |s, vf| {
                s.exprs(args, &mut |s, vs| {
                    let d = s.depth();
                    let t = vs.iter().fold(vf.at(d), |f, v| mk::app(f, v.at(d)));
                    s.cont(k, t)
                })
            }),
        }
    }

    /// A ghost lambda `|x: A, y: B| e`: the curried `λ(x : ⟦A⟧). λ(y : ⟦B⟧). ⟦e⟧`.
    /// The body is elaborated under the binders, so its obligations (partial
    /// operations, callee `requires`) are proven there, with the facts of the
    /// enclosing context; its value is closed over the enclosing locals.
    fn lambda(&mut self, params: &'a [LocalId], body: &'a Expr, span: Span) -> R<Tm> {
        let saved = self.f.scope.clone();
        let r = (|| {
            let mut binders = Vec::new();
            for p in params {
                let decl = self.local_decl(*p);
                let t = self.ty(&decl.ty, span)?;
                let lvl = self.push(&decl.name, Rel::Rel, &t, None)?;
                self.f.scope.locals.insert(*p, lvl);
                binders.push((decl.name.clone(), t));
            }
            let mut t = if body.ty == Ty::Prop { self.prop(body)? } else { self.expr(body, &mut |s, v| Ok(v.at(s.depth())))? };
            for (n, ty) in binders.into_iter().rev() {
                t = mk::lam(&n, Rel::Rel, ty, t);
            }
            Ok(t)
        })();
        self.f.scope = saved;
        r
    }

    /// Elaborates a list of expressions left to right.
    pub fn exprs(&mut self, es: &'a [Expr], k: &mut dyn FnMut(&mut Elab<'a>, Vec<Val>) -> R<Tm>) -> R<Tm> {
        let refs: Vec<&'a Expr> = es.iter().collect();
        self.exprs_ref(&refs, k)
    }

    /// [`Elab::exprs`] over references.
    pub fn exprs_ref(&mut self, es: &[&'a Expr], k: &mut dyn FnMut(&mut Elab<'a>, Vec<Val>) -> R<Tm>) -> R<Tm> {
        self.exprs_from(es, Vec::new(), k)
    }

    fn exprs_from(&mut self, es: &[&'a Expr], acc: Vec<Val>, k: &mut dyn FnMut(&mut Elab<'a>, Vec<Val>) -> R<Tm>) -> R<Tm> {
        match es.split_first() {
            None => k(self, acc),
            Some((first, rest)) => {
                let rest: Vec<&'a Expr> = rest.to_vec();
                self.expr(first, &mut |s, v| {
                    let mut acc2 = acc.clone();
                    acc2.push(v);
                    s.exprs_from(&rest, acc2, k)
                })
            }
        }
    }

    /// Literal terms.
    pub fn lit_tm(&self, l: &Lit, ty: &Ty, span: Span) -> R<Tm> {
        match l {
            Lit::Bool(b) => Ok(self.bool_lit(*b)),
            Lit::Int(n) => match ty.peel_refs() {
                Ty::Uint(w) => Ok(mk::lit(w.width(), *n)),
                Ty::Int | Ty::Nat => Ok(mk::lit(Width::Int, *n)),
                other => internal(span, format!("integer literal of type `{}`", self.krate.ty_str(other))),
            },
        }
    }

    // ------------------------------------------------------------------
    // operators
    // ------------------------------------------------------------------

    /// A checked primitive with its proof slots proven (§5.7).
    pub fn checked_prim(&mut self, op: PrimOp, args: Vec<Tm>, kind: ObligationKind, span: Span) -> R<Tm> {
        let obls = sandblaster_kernel::prim::prim_obligations(op, &args, self.p.bool_);
        let mut proofs = Vec::new();
        for o in obls {
            proofs.push(self.prove(kind.clone(), span, &o, false)?);
        }
        Ok(mk::prim(op, args, proofs))
    }

    pub(crate) fn p0(&self, op: PrimOp, args: Vec<Tm>) -> Tm {
        mk::prim(op, args, vec![])
    }

    /// `a op b` on scalars (§3.3, §3.5).
    pub fn binop(&mut self, op: BinOp, lt: &Ty, rt: &Ty, a: Tm, b: Tm, span: Span) -> R<Tm> {
        let (lp, rp) = (lt.peel_refs(), rt.peel_refs());
        match (lp, rp) {
            (Ty::Uint(w), Ty::Uint(w2)) if op.is_shift() => self.shift_op(op, *w, *w2, a, b, span),
            (Ty::Uint(w), Ty::Uint(_)) => {
                let w = w.width();
                Ok(match op {
                    BinOp::Add => self.checked_prim(PrimOp::Add(w), vec![a, b], ObligationKind::Overflow, span)?,
                    BinOp::Sub => self.checked_prim(PrimOp::Sub(w), vec![a, b], ObligationKind::Underflow, span)?,
                    BinOp::Mul => self.checked_prim(PrimOp::Mul(w), vec![a, b], ObligationKind::Overflow, span)?,
                    BinOp::Div => self.checked_prim(PrimOp::Div(w), vec![a, b], ObligationKind::DivZero, span)?,
                    BinOp::Rem => self.checked_prim(PrimOp::Rem(w), vec![a, b], ObligationKind::DivZero, span)?,
                    BinOp::BitAnd => self.p0(PrimOp::And(w), vec![a, b]),
                    BinOp::BitOr => self.p0(PrimOp::Or(w), vec![a, b]),
                    BinOp::BitXor => self.p0(PrimOp::Xor(w), vec![a, b]),
                    BinOp::Eq => self.p0(PrimOp::Eq(w), vec![a, b]),
                    BinOp::Ne => self.p0(PrimOp::Ne(w), vec![a, b]),
                    BinOp::Lt => self.p0(PrimOp::Lt(w), vec![a, b]),
                    BinOp::Le => self.p0(PrimOp::Le(w), vec![a, b]),
                    BinOp::Gt => self.p0(PrimOp::Gt(w), vec![a, b]),
                    BinOp::Ge => self.p0(PrimOp::Ge(w), vec![a, b]),
                    BinOp::Shl | BinOp::Shr | BinOp::And | BinOp::Or => return internal(span, "operator reached the scalar case"),
                })
            }
            (Ty::Int | Ty::Nat, Ty::Int | Ty::Nat) => {
                let i = Width::Int;
                let nat = matches!((lp, rp), (Ty::Nat, Ty::Nat));
                Ok(match op {
                    BinOp::Add => self.p0(PrimOp::IAdd, vec![a, b]),
                    BinOp::Sub if nat => {
                        // `Nat - Nat` (§4.1): `b ≤ a`, kept as an irrelevant
                        // `let` so the kernel checks it (SEMANTICS.md §13.5)
                        let le = self.holds(self.p0(PrimOp::Le(i), vec![b.clone(), a.clone()]));
                        let pf = self.prove(ObligationKind::Underflow, span, &le, false)?;
                        mk::let_("h_nat", Rel::Irr, le, pf, self.p0(PrimOp::ISub, vec![shift(&a, 1), shift(&b, 1)]))
                    }
                    BinOp::Sub => self.p0(PrimOp::ISub, vec![a, b]),
                    BinOp::Mul => self.p0(PrimOp::IMul, vec![a, b]),
                    BinOp::Div | BinOp::Rem => {
                        // ghost division (§4.1): a non-zero divisor and, on
                        // `Int`, non-negative operands (then truncating and
                        // Euclidean division agree; `Nat` operands are
                        // non-negative by construction); kept as irrelevant
                        // `let`s so the kernel checks them (SEMANTICS.md §13.5)
                        let mut goals = Vec::new();
                        if !nat {
                            goals.push(self.holds(self.p0(PrimOp::Le(i), vec![mk::lit(i, 0u8), a.clone()])));
                            goals.push(self.holds(self.p0(PrimOp::Le(i), vec![mk::lit(i, 0u8), b.clone()])));
                        }
                        goals.push(self.holds(self.p0(PrimOp::Ne(i), vec![b.clone(), mk::lit(i, 0u8)])));
                        // each goal is proven here, at the current depth; its
                        // `let` is nested under the `k` earlier ones, so the
                        // goal and its proof are shifted by `k` there
                        let mut proofs = Vec::new();
                        for (k, g) in goals.iter().enumerate() {
                            let kind = if k + 1 == goals.len() { ObligationKind::DivZero } else { ObligationKind::WellFormed };
                            proofs.push(self.prove(kind, span, g, false)?);
                        }
                        let n = goals.len() as i64;
                        let iop = if op == BinOp::Div { PrimOp::IDiv } else { PrimOp::IMod };
                        let mut t = self.p0(iop, vec![shift(&a, n), shift(&b, n)]);
                        for (k, (g, pf)) in goals.iter().zip(proofs).enumerate().rev() {
                            t = mk::let_(if k + 1 == goals.len() { "h_div" } else { "h_nonneg" }, Rel::Irr, shift(g, k as i64), shift(&pf, k as i64), t);
                        }
                        t
                    }
                    BinOp::Eq => self.p0(PrimOp::Eq(i), vec![a, b]),
                    BinOp::Ne => self.p0(PrimOp::Ne(i), vec![a, b]),
                    BinOp::Lt => self.p0(PrimOp::Lt(i), vec![a, b]),
                    BinOp::Le => self.p0(PrimOp::Le(i), vec![a, b]),
                    BinOp::Gt => self.p0(PrimOp::Gt(i), vec![a, b]),
                    BinOp::Ge => self.p0(PrimOp::Ge(i), vec![a, b]),
                    _ => return unsupported(span, format!("`{}` on `Int`", op.symbol())),
                })
            }
            (Ty::Bool, Ty::Bool) => {
                let g = match op {
                    BinOp::BitAnd => "bool::and",
                    BinOp::BitOr => "bool::or",
                    BinOp::BitXor => "bool::xor",
                    BinOp::Eq => "bool::eq",
                    BinOp::Ne => "bool::ne",
                    _ => return internal(span, format!("`{}` on bool", op.symbol())),
                };
                Ok(mk::apps(mk::global(self.p.g(g)), [(Rel::Rel, a), (Rel::Rel, b)]))
            }
            _ if matches!(op, BinOp::Eq | BinOp::Ne) => {
                let eq = self.struct_eq(lp, rp, a, b, span)?;
                Ok(if op == BinOp::Ne { mk::app(mk::global(self.p.g("bool::not")), eq) } else { eq })
            }
            _ => internal(span, format!("`{}` on `{}` and `{}`", op.symbol(), self.krate.ty_str(lt), self.krate.ty_str(rt))),
        }
    }

    /// `a << s` / `a >> s`: checked shift at the width of `a`; the amount
    /// is converted to `u32`. For amounts wider than 32 bits the obligation
    /// `s < bits` is proven at the amount's own width first (rustc panics
    /// on `s ≥ bits` even when `s mod 2^32` is small), and the prim's slot is
    /// derived from it by linear arithmetic.
    fn shift_op(&mut self, op: BinOp, w: UintTy, w2: UintTy, a: Tm, s: Tm, span: Span) -> R<Tm> {
        let pop = if op == BinOp::Shl { PrimOp::Shl(w.width()) } else { PrimOp::Shr(w.width()) };
        let bits = w.bits();
        if w2.bits() <= 32 {
            let s32 = if w2 == UintTy::U32 { s } else { self.p0(PrimOp::Cast { from: w2.width(), to: Width::U32 }, vec![s]) };
            return self.checked_prim(pop, vec![a, s32], ObligationKind::ShiftWidth, span);
        }
        let wide = self.holds(self.p0(PrimOp::Lt(w2.width()), vec![s.clone(), mk::lit(w2.width(), bits)]));
        let p1 = self.prove(ObligationKind::ShiftWidth, span, &wide, false)?;
        let s32 = self.p0(PrimOp::Cast { from: w2.width(), to: Width::U32 }, vec![s]);
        let goal = self.holds(self.p0(PrimOp::Lt(Width::U32), vec![s32.clone(), mk::lit(Width::U32, bits)]));
        let pf = if matches!(&*p1, Term::Erased) { p1 } else { super::basic::linarith_term(&self.env, &self.f.scope.ctx, vec![(p1, wide)], goal).map_err(|e| ElabError { span, msg: format!("shift amount conversion: {e}"), kind: ErrKind::Internal })? };
        Ok(mk::prim(pop, vec![a, s32], vec![pf]))
    }

    /// Unary operators.
    pub fn unary(&mut self, op: UnOp, t: &Ty, x: Tm, span: Span) -> R<Tm> {
        match (op, t.peel_refs()) {
            (UnOp::Not, Ty::Bool) => Ok(mk::app(mk::global(self.p.g("bool::not")), x)),
            (UnOp::Not, Ty::Uint(w)) => Ok(self.p0(PrimOp::Not(w.width()), vec![x])),
            (UnOp::Neg, Ty::Int) => Ok(self.p0(PrimOp::INeg, vec![x])),
            (_, other) => internal(span, format!("unary operator on `{}`", self.krate.ty_str(other))),
        }
    }

    /// `x as T` (§3.3): widening exact, narrowing truncating, `bool as uN`
    /// is 0/1, `as Int` exact.
    pub fn cast(&mut self, from: &Ty, to: &Ty, x: Tm, span: Span) -> R<Tm> {
        match (from.peel_refs(), to) {
            (Ty::Uint(a), Ty::Uint(b)) if a == b => Ok(x),
            (Ty::Uint(a), Ty::Uint(b)) => Ok(self.p0(PrimOp::Cast { from: a.width(), to: b.width() }, vec![x])),
            (Ty::Uint(a), Ty::Int | Ty::Nat) => Ok(self.p0(PrimOp::Cast { from: a.width(), to: Width::Int }, vec![x])),
            (Ty::Int | Ty::Nat, Ty::Int) | (Ty::Nat, Ty::Nat) => Ok(x),
            (Ty::Int, Ty::Nat) => {
                // `Int as Nat` (§4.1): `0 ≤ x`
                let g = self.holds(self.p0(PrimOp::Le(Width::Int), vec![mk::lit(Width::Int, 0u8), x.clone()]));
                let pf = self.prove(ObligationKind::Underflow, span, &g, false)?;
                Ok(mk::let_("h_nat", Rel::Irr, g, pf, shift(&x, 1)))
            }
            (Ty::Int | Ty::Nat, Ty::Uint(b)) => Ok(self.int_trunc(*b, x, span)?),
            (Ty::Bool, Ty::Uint(b)) => Ok(mk::app(mk::global(self.p.g(&format!("bool::as_{}", b.name()))), x)),
            (Ty::Bool, Ty::Int | Ty::Nat) => Ok(self.p0(PrimOp::Cast { from: Width::U8, to: Width::Int }, vec![mk::app(mk::global(self.p.g("bool::as_u8")), x)])),
            (f, t) => internal(span, format!("cast from `{}` to `{}`", self.krate.ty_str(f), self.krate.ty_str(t))),
        }
    }

    /// Ghost `x as uN` for `x : Int | Nat` (§4.1): truncation mod 2^N,
    /// exactly like exec `as` — `of_int_w(imod(x, 2^N))` (the range proofs
    /// of `of_int` hold for every `x`).
    pub fn int_trunc(&mut self, u: UintTy, x: Tm, span: Span) -> R<Tm> {
        let (int, w) = (Width::Int, u.width());
        let m = self.p0(PrimOp::IMod, vec![x, mk::lit(int, num_bigint::BigInt::from(1u8) << u.bits())]);
        let obls = sandblaster_kernel::prim::prim_obligations(PrimOp::OfInt(w), std::slice::from_ref(&m), self.p.bool_);
        let mut proofs = Vec::new();
        for o in obls {
            proofs.push(self.prove(ObligationKind::WellFormed, span, &o, false)?);
        }
        Ok(mk::prim(PrimOp::OfInt(w), vec![m], proofs))
    }

    /// `&[T; N] → &[T]`.
    pub fn unsize(&mut self, from: &Ty, x: Tm, span: Span) -> R<Tm> {
        match from.peel_refs() {
            Ty::Array(e, n) => self.as_slice(e, *n, x, span),
            Ty::Slice(_) => Ok(x),
            other => internal(span, format!("unsizing `{}`", self.krate.ty_str(other))),
        }
    }

    /// `array::as_slice T N a .hN` (`N ≤ ISIZE_MAX` by evaluation).
    pub fn as_slice(&mut self, elem: &Ty, n: u64, a: Tm, span: Span) -> R<Tm> {
        let et = self.ty(elem, span)?;
        let bound = self.holds(self.p0(PrimOp::Le(Width::Int), vec![mk::lit(Width::Int, n), mk::global(self.p.g("ISIZE_MAX"))]));
        let pf = self.prove(ObligationKind::WellFormed, span, &bound, false)?;
        Ok(mk::apps(mk::global(self.p.g("array::as_slice")), [(Rel::Rel, et), (Rel::Rel, mk::lit(Width::Usize, n)), (Rel::Rel, a), (Rel::Irr, pf)]))
    }

    /// Field `index` of a struct or tuple value.
    pub fn field(&mut self, base_ty: &Ty, b: Tm, index: usize, span: Span) -> R<Tm> {
        let bt = base_ty.peel_refs();
        let (ind, params) = self.ind_of(bt, span)?;
        let ftys = self.ctor_field_tys(bt, 0, span)?;
        let fty = self.ty(&ftys[index], span)?;
        Ok(self.proj(ind, params, b, index, ftys.len(), fty))
    }

    /// `base[i]` (§3.3): `array::index` / `slice::index` with an
    /// `IndexBounds` obligation.
    pub fn index(&mut self, base_ty: &Ty, b: Tm, i: Tm, span: Span) -> R<Tm> {
        match base_ty.peel_refs() {
            Ty::Array(e, n) => {
                let et = self.ty(e, span)?;
                let goal = self.holds(self.p0(PrimOp::Lt(Width::Usize), vec![i.clone(), mk::lit(Width::Usize, *n)]));
                let pf = self.prove(ObligationKind::IndexBounds, span, &goal, false)?;
                Ok(mk::apps(mk::global(self.p.g("array::index")), [(Rel::Rel, et), (Rel::Rel, mk::lit(Width::Usize, *n)), (Rel::Rel, b), (Rel::Rel, i), (Rel::Irr, pf)]))
            }
            Ty::Slice(e) => {
                let et = self.ty(e, span)?;
                let goal = self.holds(self.p0(PrimOp::Lt(Width::Usize), vec![i.clone(), mk::fst(b.clone())]));
                let pf = self.prove(ObligationKind::IndexBounds, span, &goal, false)?;
                Ok(mk::apps(mk::global(self.p.g("slice::index")), [(Rel::Rel, et), (Rel::Rel, b), (Rel::Rel, i), (Rel::Irr, pf)]))
            }
            other => internal(span, format!("indexing `{}`", self.krate.ty_str(other))),
        }
    }

    /// `&base[lo..hi]` (§3.3) with `SliceRange` obligations.
    pub fn slice_range(&mut self, base_ty: &Ty, b: Tm, lo: Option<Tm>, hi: Option<Tm>, span: Span) -> R<Tm> {
        let (elem, s) = match base_ty.peel_refs() {
            Ty::Array(e, n) => ((**e).clone(), self.as_slice(e, *n, b, span)?),
            Ty::Slice(e) => ((**e).clone(), b),
            other => return internal(span, format!("range of `{}`", self.krate.ty_str(other))),
        };
        let et = self.ty(&elem, span)?;
        let le = |me: &Self, x: Tm, y: Tm| me.holds(me.p0(PrimOp::Le(Width::Usize), vec![x, y]));
        let len = mk::fst(s.clone());
        Ok(match (lo, hi) {
            (None, None) => s,
            (Some(lo), None) => {
                let g = le(self, lo.clone(), len);
                let p = self.prove(ObligationKind::SliceRange, span, &g, false)?;
                mk::apps(mk::global(self.p.g("slice::suffix")), [(Rel::Rel, et), (Rel::Rel, s), (Rel::Rel, lo), (Rel::Irr, p)])
            }
            (None, Some(hi)) => {
                let g = le(self, hi.clone(), len);
                let p = self.prove(ObligationKind::SliceRange, span, &g, false)?;
                mk::apps(mk::global(self.p.g("slice::prefix")), [(Rel::Rel, et), (Rel::Rel, s), (Rel::Rel, hi), (Rel::Irr, p)])
            }
            (Some(lo), Some(hi)) => {
                let g0 = le(self, lo.clone(), hi.clone());
                let p0 = self.prove(ObligationKind::SliceRange, span, &g0, false)?;
                let g1 = le(self, hi.clone(), len);
                let p1 = self.prove(ObligationKind::SliceRange, span, &g1, false)?;
                mk::apps(mk::global(self.p.g("slice::range")), [(Rel::Rel, et), (Rel::Rel, s), (Rel::Rel, lo), (Rel::Rel, hi), (Rel::Irr, p0), (Rel::Irr, p1)])
            }
        })
    }

    /// Constructor applications (struct literals incl. `..base`, tuple
    /// structs, variants, `Some`, `None`).
    fn adt_value(&mut self, e: &'a Expr, ctor: Ctor, ty_args: &[Ty], fields: &[(u32, Expr)], has_base: bool, vs: Vec<Val>) -> R<Tm> {
        let span = e.span;
        let d = self.depth();
        let params = ty_args.iter().map(|t| self.ty(t, span)).collect::<R<Vec<_>>>()?;
        match ctor {
            Ctor::Some => Ok(mk::ctor(self.p.option, 1, params, vec![vs[0].at(d)])),
            Ctor::None => Ok(mk::ctor(self.p.option, 0, params, vec![])),
            Ctor::Struct(id) | Ctor::Variant(id, _) => {
                let ind = self.adt(id, span)?;
                let (cidx, ftys): (u32, Vec<Ty>) = match (ctor, &self.krate.item(id).kind) {
                    (Ctor::Struct(_), ItemKind::Struct(s)) => (0, s.fields.iter().map(|f| f.ty.subst(ty_args)).collect()),
                    (Ctor::Variant(_, v), ItemKind::Enum(en)) => (v, en.variants[v as usize].fields.iter().map(|f| f.ty.subst(ty_args)).collect()),
                    _ => return internal(span, "constructor/item mismatch"),
                };
                let mut args: Vec<Option<Tm>> = vec![None; ftys.len()];
                for (j, (fi, _)) in fields.iter().enumerate() {
                    args[*fi as usize] = Some(vs[j].at(d));
                }
                if has_base {
                    let base = vs[fields.len()].at(d);
                    for (k, a) in args.iter_mut().enumerate() {
                        if a.is_none() {
                            let fty = self.ty(&ftys[k], span)?;
                            *a = Some(self.proj(ind, params.clone(), base.clone(), k, ftys.len(), fty));
                        }
                    }
                }
                let args = args.into_iter().map(|a| a.ok_or_else(|| ElabError { span, msg: "missing field".into(), kind: ErrKind::Internal })).collect::<R<Vec<_>>>()?;
                // the invariant's `Irr` fields (§15.3): literal, tuple-struct
                // call and `..base` update alike
                self.ctor_with_invariants(ind, cidx, params, args, Some(id), span)
            }
        }
    }

    // ------------------------------------------------------------------
    // calls
    // ------------------------------------------------------------------

    fn call(&mut self, e: &'a Expr, callee: &'a Callee, vs: Vec<Val>, k: &mut K<'_, 'a>) -> R<Tm> {
        let span = e.span;
        let d = self.depth();
        let args: Vec<Tm> = vs.iter().map(|v| v.at(d)).collect();
        match callee {
            Callee::Item(id, targs) => {
                let (t, all) = self.item_call_full(*id, targs, args, span)?;
                // the callee's `ensures` (DESIGN.md §7.3) and refinement
                // (§15.2) become facts — not for a hypothetical `F'` (§15.5)
                let mut facts = Vec::new();
                let abstracted = self.f.abstracted.contains_key(id);
                if !abstracted && let Some(x) = self.callee_ensures(*id, &all) {
                    facts.push(("h_ens", x));
                }
                if !abstracted && let Some(x) = self.callee_refines(*id, &all) {
                    facts.push(("h_ref", x));
                }

                let tv = Val::new(t, self.depth());
                self.call_facts(&facts, 0, span, &mut |s| {
                    // the invariant facts of the result (§15.3)
                    s.with_inv_facts(&tv, &e.ty, span, &mut |s| {
                        let t = tv.at(s.depth());
                        s.cont(k, t)
                    })
                })
            }
            Callee::Builtin(b, targs) => self.builtin_call(*b, targs, args, span, k),
            Callee::Intrinsic(i, imms) => {
                let t = self.intrinsic_call(*i, imms, args, span)?;
                self.cont(k, t)
            }
            Callee::Ghost(g, targs) => {
                let t = self.ghost_call(*g, targs, args, span)?;
                self.cont(k, t)
            }
        }
    }

    /// Binds the contract facts of a call (see [`Elab::call`]); the facts
    /// are closed terms of the call's depth, shifted as binders are added.
    #[allow(clippy::type_complexity)]
    fn call_facts(&mut self, facts: &[(&str, (sandblaster_kernel::term::GlobalId, Tm, Tm))], i: usize, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let Some((name, (g, ty, pf))) = facts.get(i) else { return k(self) };
        let (ty, pf) = (shift(ty, i as i64), shift(pf, i as i64));
        self.fact_in(name, ty, pf, FactOrigin::CalleeEnsures(*g), span, &mut |s| s.call_facts(facts, i + 1, span, k))
    }

    /// A call of a user function: `f T.. args.. proofs..`, or `Rec` for a
    /// self call (with the measure proof).
    pub fn item_call(&mut self, id: ItemId, targs: &[Ty], args: Vec<Tm>, span: Span) -> R<Tm> {
        Ok(self.item_call_full(id, targs, args, span)?.0)
    }

    /// The `ensures` fact of a call of `id` with the arguments `all` (type
    /// and value arguments, then the `requires` proofs): `(g::ensures,
    /// Q[args, g args], g::ensures args proofs)`, when `g::ensures` was
    /// checked.
    pub fn callee_ensures(&mut self, id: ItemId, all: &[Tm]) -> Option<(sandblaster_kernel::term::GlobalId, Tm, Tm)> {
        let name = format!("{}::ensures", self.krate.item(id).path);
        if !self.defs.iter().any(|d| d.name == name && d.status == super::DefStatus::Checked) {
            return None;
        }
        let eg = self.env.lookup_global(&name)?;
        // the same telescope as the function (type and value parameters,
        // `requires`, the stack-depth hypothesis), all relevant
        let n = self.env.global_param_rels(eg)?.len();
        if all.len() < n {
            return None;
        }
        let args = &all[..n];
        let mut t = self.env.global_type(eg)?;
        for _ in 0..n {
            let next = match &*t {
                Term::Pi { cod, .. } => cod.clone(),
                _ => return None,
            };
            t = next;
        }
        let ty = super::tm::subst_closed(&t, args);
        let proof = mk::apps(mk::global(eg), args.iter().map(|a| (Rel::Rel, a.clone())));
        Some((eg, ty, proof))
    }

    /// [`Self::item_call`], also returning all argument terms (relevant
    /// arguments and proofs, in telescope order).
    pub fn item_call_full(&mut self, id: ItemId, targs: &[Ty], args: Vec<Tm>, span: Span) -> R<(Tm, Vec<Tm>)> {
        let tys = targs.iter().map(|t| self.ty(t, span)).collect::<R<Vec<_>>>()?;
        let mut rel_args: Vec<(Rel, Tm)> = tys.into_iter().map(|t| (Rel::Rel, t)).collect();
        // the arguments of `#[ghost]` parameters are irrelevant (DESIGN.md
        // §15.3); the callee's own lemmas take them relevantly
        let ghosts: Vec<bool> = match self.krate.fn_def(id) {
            Some(f) if f.kind == FnKind::Exec => f.params.iter().map(|p| p.ghost).collect(),
            _ => vec![],
        };
        // the values of the callee's `#[ghost]` parameters go into its ghost
        // bundle (§15.3). With exactly the other arguments given, the bundle
        // is left to the prover.
        let nghost = ghosts.iter().filter(|g| **g).count();
        let omitted = nghost > 0 && args.len() + nghost == ghosts.len();
        let mut ghost_vals = Vec::new();
        for (i, a) in args.into_iter().enumerate() {
            if !omitted && ghosts.get(i).copied().unwrap_or(false) {
                ghost_vals.push(a);
            } else {
                rel_args.push((Rel::Rel, a));
            }
        }
        let ghost = (nghost > 0 && !omitted).then_some(ghost_vals);
        let depth_req = self.depth_req_index(id);
        let is_rec = self.f.rec.as_ref().is_some_and(|r| r.item == Some(id));
        if is_rec {
            let r = self.f.rec.clone().unwrap();
            let (_, all, _) = self.apply_tele_args(&r.ty, rel_args, ghost, None, None, &|i| if Some(i) == depth_req { ObligationKind::StackDepth } else { ObligationKind::CalleeRequires(sandblaster_kernel::term::GlobalId(u32::MAX)) }, span)?;
            let proof = match &r.measure {
                Some((m, w)) => Some(self.measure_proof(m, *w, r.arity, &all, span)?),
                None => None,
            };
            return Ok((Rc::new(Term::Rec { args: all.clone(), proof }), all));
        }
        // a member of the section a `#[proof(complete = p)]` script reasons
        // about: the hypothetical implementation `F'` (§15.5)
        if let Some((lvl, fty)) = self.f.abstracted.get(&id).cloned() {
            let d = self.depth();
            let ty = shift(&fty, (d - lvl) as i64);
            let head = self.f.scope.var(lvl);
            let g = self.item_global(id, span)?;
            let (app, all, _) = self.apply_tele_args(&ty, rel_args, ghost, Some(head), None, &|_| ObligationKind::CalleeRequires(g), span)?;
            return Ok((app, all));
        }
        let g = self.item_global(id, span)?;
        let ty = self.env.global_type(g).ok_or_else(|| ElabError { span, msg: "global without type".into(), kind: ErrKind::Internal })?;
        let (app, all, _) = self.apply_tele_args(&ty, rel_args, ghost, Some(mk::global(g)), None, &|i| if Some(i) == depth_req { ObligationKind::StackDepth } else { ObligationKind::CalleeRequires(g) }, span)?;
        Ok((app, all))
    }

    /// Index (among the irrelevant binders) of the stack-depth requires of
    /// a function with `decreases(.., max = C)`.
    fn depth_req_index(&self, id: ItemId) -> Option<usize> {
        let f = self.krate.fn_def(id)?;
        f.decreases.as_ref().and_then(|d| d.max).map(|_| f.requires.len())
    }

    /// Instantiates a closed Π telescope term with the relevant arguments,
    /// proving every irrelevant binder (`requires`) on the way; with
    /// `hyps = Some(relevant)` (lemmas), every binder after the arguments is
    /// a hypothesis to prove. Obligation targets are built by
    /// **substitution** into the telescope (never by quoting values, whose
    /// instantiated proofs may not re-check). Returns the application (if
    /// `head` is given), all argument terms (relevant and proofs, in order)
    /// and the instantiated result type.
    #[allow(clippy::type_complexity)]
    pub fn apply_tele(&mut self, ty: &Tm, rel_args: Vec<Tm>, head: Option<Tm>, hyps: Option<bool>, kind_of: &dyn Fn(usize) -> ObligationKind, span: Span) -> R<(Tm, Vec<Tm>, Tm)> {
        self.apply_tele_args(ty, rel_args.into_iter().map(|a| (Rel::Rel, a)).collect(), None, head, hyps, kind_of, span)
    }

    /// [`Elab::apply_tele`] with arguments of either relevance: an `Irr`
    /// argument is supplied for an `Irr` binder (a `#[ghost]` parameter,
    /// DESIGN.md §15.3) instead of proving it; every other `Irr` binder is
    /// an obligation.
    ///
    /// With `ghost` (the values of a callee's `#[ghost]` parameters, §15.3),
    /// the first binder after the relevant arguments is the ghost bundle:
    /// it gets the values and proofs of the callee's ghost `requires`
    /// ([`Elab::ghost_bundle_arg`]).
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn apply_tele_args(&mut self, ty: &Tm, args: Vec<(Rel, Tm)>, ghost: Option<Vec<Tm>>, head: Option<Tm>, hyps: Option<bool>, kind_of: &dyn Fn(usize) -> ObligationKind, span: Span) -> R<(Tm, Vec<Tm>, Tm)> {
        self.apply_tele_upto(ty, args, ghost, head, hyps, None, kind_of, span)
    }

    /// [`Elab::apply_tele_args`] consuming at most `max` binders (a lemma's
    /// arity: its parameters and `requires`). The rest of the telescope is
    /// the lemma's conclusion: an `ensures(implies(a, b))` is the fact
    /// `a -> b` at the call, not a hypothesis `a` to prove.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn apply_tele_upto(&mut self, ty: &Tm, args: Vec<(Rel, Tm)>, ghost: Option<Vec<Tm>>, head: Option<Tm>, hyps: Option<bool>, max: Option<usize>, kind_of: &dyn Fn(usize) -> ObligationKind, span: Span) -> R<(Tm, Vec<Tm>, Tm)> {
        let mut app = head.unwrap_or_else(|| Rc::new(Term::Erased));
        let mut all: Vec<Tm> = Vec::new();
        let mut it = args.into_iter().peekable();
        let mut ghost = ghost;
        let mut hyp_i = 0usize;
        let mut t = ty.clone();
        loop {
            if max.is_some_and(|m| all.len() >= m) && it.peek().is_none() && ghost.is_none() {
                break;
            }
            let Term::Pi { rel, dom, cod, .. } = &*t.clone() else { break };
            let next_rel = it.peek().map(|(r, _)| *r);
            let arg = match (rel, next_rel, hyps) {
                (Rel::Rel, Some(Rel::Rel), _) | (Rel::Irr, Some(Rel::Irr), _) => it.next().unwrap().1,
                (Rel::Rel, Some(Rel::Irr), _) => return internal(span, "an irrelevant argument for a relevant parameter"),
                (Rel::Irr, None, _) if ghost.is_some() => {
                    let vals = ghost.take().unwrap();
                    let target = super::tm::subst_closed(dom, &all);
                    self.ghost_bundle_arg(&target, &vals, kind_of(usize::MAX), span)?
                }
                (Rel::Rel, None, None) => break,
                (_, _, _) => {
                    let target = super::tm::subst_closed(dom, &all);
                    let relevant = matches!(hyps, Some(true)) && *rel == Rel::Rel;
                    let p = self.prove(kind_of(hyp_i), span, &target, relevant)?;
                    hyp_i += 1;
                    p
                }
            };
            app = Rc::new(Term::App { rel: *rel, fun: app, arg: arg.clone() });
            all.push(arg);
            t = cod.clone();
            if hyps.is_none() && it.peek().is_none() && ghost.is_none() && !matches!(&*t, Term::Pi { rel: Rel::Irr, .. }) {
                break;
            }
        }
        if it.next().is_some() {
            return internal(span, "too many arguments for the callee's telescope");
        }
        let res = super::tm::subst_closed(&t, &all);
        let res = super::recert::recertify(&self.env, &self.f.scope.ctx, &res);
        Ok((app, all, res))
    }

    /// The decrease proof of a measure-recursive call (§5.6):
    /// `m[args] < m[params]` (with `0 ≤ m[args]` for `Int` measures).
    pub fn measure_proof(&mut self, m: &Tm, w: Width, arity: u32, args: &[Tm], span: Span) -> R<Tm> {
        let ma = super::tm::subst_closed(m, &args[..arity as usize]);
        let mp = shift(m, (self.depth() - arity) as i64);
        if w == Width::Int {
            let g0 = self.holds(self.p0(PrimOp::Le(Width::Int), vec![mk::lit(Width::Int, 0u8), ma.clone()]));
            let p0 = self.prove(ObligationKind::Termination, span, &g0, false)?;
            let g1 = self.holds(self.p0(PrimOp::Lt(Width::Int), vec![ma, mp]));
            let p1 = self.prove(ObligationKind::Termination, span, &g1, false)?;
            let ty = mk::sigma("_", Rel::Rel, g0, shift(&g1, 1));
            Ok(mk::pair(ty, p0, p1))
        } else {
            let g = self.holds(self.p0(PrimOp::Lt(w), vec![ma, mp]));
            self.prove(ObligationKind::Termination, span, &g, false)
        }
    }

    // ------------------------------------------------------------------
    // builtin methods (§3.4)
    // ------------------------------------------------------------------

    fn builtin_call(&mut self, b: Builtin, targs: &[Ty], args: Vec<Tm>, span: Span, k: &mut K<'_, 'a>) -> R<Tm> {
        let rel = |ts: Vec<Tm>| ts.into_iter().map(|t| (Rel::Rel, t)).collect::<Vec<_>>();
        let elem = || -> R<Tm> {
            match targs.first() {
                Some(t) => self.ty(t, span),
                None => internal(span, "builtin without element type"),
            }
        };
        let t = match b {
            Builtin::Int(m, w) => {
                use IntMethod::*;
                if m == DivCeil {
                    // `a.div_ceil(b)` (lift.core): panics exactly when `b == 0`
                    let name = format!("{}::div_ceil", w.name());
                    let Some(gid) = self.env.lookup_global(&name) else { return unsupported(span, format!("`{name}` has no definition")) };
                    let kw = w.width();
                    let mut it = args.into_iter();
                    let (a, b2) = (it.next().unwrap(), it.next().unwrap());
                    let goal = self.holds(self.p0(PrimOp::Ne(kw), vec![b2.clone(), mk::lit(kw, 0u8)]));
                    let p = self.prove(ObligationKind::DivZero, span, &goal, false)?;
                    let t = mk::apps(mk::global(gid), [(Rel::Rel, a), (Rel::Rel, b2), (Rel::Irr, p)]);
                    return self.with_method_facts(b, targs, t, span, k);
                }
                let name = match m {
                    Pow | DivCeil => return unsupported(span, format!("`{}` has no prelude definition yet", m.name())),
                    ToBeBytes | ToLeBytes | FromBeBytes | FromLeBytes if matches!(w, UintTy::U8 | UintTy::Usize) => {
                        return unsupported(span, format!("`{}::{}` has no prelude definition yet", w.name(), m.name()));
                    }
                    _ => format!("{}::{}", w.name(), m.name()),
                };
                let Some(g) = self.env.lookup_global(&name) else { return unsupported(span, format!("`{name}` has no prelude definition")) };
                mk::apps(mk::global(g), rel(args))
            }
            Builtin::Slice(m) => {
                use SliceMethod::*;
                let et = elem()?;
                let mut it = args.into_iter();
                let s = it.next().ok_or_else(|| ElabError { span, msg: "slice method without receiver".into(), kind: ErrKind::Internal })?;
                let g = |me: &Self, n: &str| mk::global(me.p.g(n));
                match m {
                    Len => mk::fst(s),
                    IsEmpty => mk::apps(g(self, "slice::is_empty"), rel(vec![et, s])),
                    First => mk::apps(g(self, "slice::first"), rel(vec![et, s])),
                    Last => mk::apps(g(self, "slice::last"), rel(vec![et, s])),
                    Get => mk::apps(g(self, "slice::get"), rel(vec![et, s, it.next().unwrap()])),
                    SplitAt => {
                        let mid = it.next().unwrap();
                        let gid = self.p.g("slice::split_at");
                        let goal = self.holds(self.p0(PrimOp::Le(Width::Usize), vec![mid.clone(), mk::fst(s.clone())]));
                        let p = self.prove(ObligationKind::CalleeRequires(gid), span, &goal, false)?;
                        mk::apps(mk::global(gid), [(Rel::Rel, et), (Rel::Rel, s), (Rel::Rel, mid), (Rel::Irr, p)])
                    }
                    SplitAtChecked => mk::apps(g(self, "slice::split_at_checked"), rel(vec![et, s, it.next().unwrap()])),
                    SplitFirst => mk::apps(g(self, "slice::split_first"), rel(vec![et, s])),
                    SplitLast => mk::apps(g(self, "slice::split_last"), rel(vec![et, s])),
                    SplitFirstChunk(n) => mk::apps(g(self, "slice::split_first_chunk"), rel(vec![et, s, mk::lit(Width::Usize, n)])),
                    FirstChunk(n) => mk::apps(g(self, "slice::first_chunk"), rel(vec![et, s, mk::lit(Width::Usize, n)])),
                    SplitLastChunk(_) => return unsupported(span, "`split_last_chunk` has no prelude definition yet"),
                    AsChunks(n) => {
                        let gid = self.p.g("slice::as_chunks");
                        let goal = self.holds(self.p0(PrimOp::Lt(Width::Usize), vec![mk::lit(Width::Usize, 0u8), mk::lit(Width::Usize, n)]));
                        let p = self.prove(ObligationKind::CalleeRequires(gid), span, &goal, false)?;
                        mk::apps(mk::global(gid), [(Rel::Rel, et), (Rel::Rel, s), (Rel::Rel, mk::lit(Width::Usize, n)), (Rel::Irr, p)])
                    }
                }
            }
            Builtin::Array(ArrayMethod::AsSlice(n)) => {
                let elem_ty = targs.first().cloned().ok_or_else(|| ElabError { span, msg: "as_slice without element type".into(), kind: ErrKind::Internal })?;
                let a = args.into_iter().next().unwrap();
                self.as_slice(&elem_ty, n, a, span)?
            }
            Builtin::Option(m) => {
                let et = elem()?;
                let name = match m {
                    OptionMethod::IsSome => "option::is_some",
                    OptionMethod::IsNone => "option::is_none",
                    OptionMethod::UnwrapOr => "option::unwrap_or",
                };
                let mut all = vec![et];
                all.extend(args);
                mk::apps(mk::global(self.p.g(name)), rel(all))
            }
            other => return internal(span, format!("operator builtin {other:?} used as a method")),
        };
        // method facts (§3.4): lemmas about the call, as facts
        self.with_method_facts(b, targs, t, span, k)
    }

    // ------------------------------------------------------------------
    // branching
    // ------------------------------------------------------------------

    /// The dependent-match idiom (§7.2) on a value of an inductive type:
    /// `match s as y return Π(e : Eq(D, s, y)). A with ..` applied to
    /// `refl(D, s)`. `arm` builds each arm body with the constructor's
    /// fields and the path equation in scope (their levels are passed).
    #[allow(clippy::type_complexity)]
    pub fn dep_match(&mut self, ind: IndId, params: Vec<Tm>, scrut: Tm, answer: &Answer, span: Span, arm: &mut dyn FnMut(&mut Elab<'a>, u32, Vec<u32>) -> R<Tm>) -> R<Tm> {
        // inside an arm of a refinement match, a nested match keeps the
        // branch goal
        let answer = match (answer, &self.f.branch_goal) {
            (Answer::Motive(_), Some(g)) => Answer::Tm(g.clone()),
            (a, _) => a.clone(),
        };
        let d = self.depth();
        let dty = mk::ind(ind, params.clone());
        // path equations of *value* matches only feed proof slots: always
        // irrelevant, so a bool/Option expression elaborates to the same term
        // in exec code and in ghost code (lemma statements must meet the
        // exec functions they talk about by conversion); proof-building
        // matches (scripts, `ensures` walkers) use the mode's relevance
        let eq_rel = match &answer {
            Answer::Ty(_) => Rel::Irr,
            _ => self.fact_rel(),
        };
        let motive = mk::pi("e", eq_rel, mk::eq(shift(&dty, 1), shift(&scrut, 1), mk::var(0)), {
            match &answer {
                Answer::Motive(m) => shift(&m.at(d + 1), 1),
                _ => {
                    // answer at depth d + 2
                    let saved = self.f.scope.clone();
                    let bty = self.eval(&dty)?;
                    self.push_v("y", Rel::Rel, bty);
                    let eqt = mk::eq(shift(&dty, 1), shift(&scrut, 1), mk::var(0));
                    self.push("e", eq_rel, &eqt, None)?;
                    let a = self.answer_tm(&answer, span);
                    self.f.scope = saved;
                    a?
                }
            }
        });
        let decl = self.env.inductive_decl(ind).ok_or_else(|| ElabError { span, msg: "unknown inductive".into(), kind: ErrKind::Internal })?;
        let pvals = params.iter().map(|p| self.eval(p)).collect::<R<Vec<_>>>()?;
        let mut arms = Vec::new();
        for (ci, c) in decl.ctors.iter().enumerate() {
            let saved = self.f.scope.clone();
            let saved_goal = self.f.branch_goal.clone();
            let mut fenv: Vec<EnvEntry> = pvals.iter().map(|v| EnvEntry::Rel(v.clone())).collect();
            let mut lvls = Vec::new();
            for (fname, frel, fty) in &c.fields {
                let ftv = self.eval_in(&VEnv(Rc::new(fenv.clone())), fty)?;
                let l = self.push_v(fname, *frel, ftv);
                fenv.push(self.f.scope.venv.0.last().cloned().unwrap());
                lvls.push(l);
            }
            let n = c.fields.len() as u32;
            let fields: Vec<Tm> = (0..n).map(|j| mk::var(n - 1 - j)).collect();
            let cval = mk::ctor(ind, ci as u32, params.iter().map(|p| shift(p, n as i64)).collect(), fields);
            if let Answer::Motive(m) = &answer {
                // goal of this arm: motive[y := C(fields)], by substitution
                // on the motive *term* (quoting the evaluated goal would
                // unfold every transparent call in it), redexes contracted
                let gt = super::tm::simp_redexes(&super::tm::subst0(&sandblaster_kernel::util::shift_from(&m.at(d + 1), n as i64, 1), &cval));
                let eqt0 = mk::eq(shift(&dty, n as i64), shift(&scrut, n as i64), cval.clone());
                self.push_fact_rel("e", eq_rel, &eqt0, None, FactOrigin::PathCond, span)?;
                self.f.branch_goal = Some(Val::new(gt, d + n));
                let body = arm(self, ci as u32, lvls);
                self.f.scope = saved;
                self.f.branch_goal = saved_goal;
                arms.push(Arm { names: c.fields.iter().map(|f| f.0.clone()).collect(), body: mk::lam("e", eq_rel, eqt0, body?) });
                continue;
            }
            let eqt = mk::eq(shift(&dty, n as i64), shift(&scrut, n as i64), cval);
            self.push_fact_rel("e", eq_rel, &eqt, None, FactOrigin::PathCond, span)?;
            let body = arm(self, ci as u32, lvls);
            self.f.scope = saved;
            self.f.branch_goal = saved_goal;
            arms.push(Arm { names: c.fields.iter().map(|f| f.0.clone()).collect(), body: mk::lam("e", eq_rel, eqt, body?) });
        }
        let m = Rc::new(Term::Match { ind, params, scrut: scrut.clone(), motive, arms });
        Ok(Rc::new(Term::App { rel: eq_rel, fun: m, arg: mk::refl(dty, scrut) }))
    }

    /// `if c { T } else { F }` as a dependent bool match; `branch` gets
    /// `true` for the then-branch.
    pub fn if_then_else(&mut self, c: Tm, answer: &Answer, span: Span, branch: &mut dyn FnMut(&mut Elab<'a>, bool) -> R<Tm>) -> R<Tm> {
        self.dep_match(self.p.bool_, vec![], c, answer, span, &mut |s, ci, _| branch(s, ci == 1))
    }

    /// `let name : ty = val; k` — pushes the binder for `k` and wraps its
    /// result (the scope is restored afterwards).
    pub fn let_in(&mut self, name: &str, rel: Rel, ty: Tm, val: Tm, k: &mut dyn FnMut(&mut Elab<'a>, u32) -> R<Tm>) -> R<Tm> {
        let saved = self.f.scope.clone();
        let lvl = self.push(name, rel, &ty, Some(&val))?;
        let body = k(self, lvl);
        self.f.scope = saved;
        Ok(mk::let_(name, rel, ty, val, body?))
    }

    /// A fact `let .name : ty = proof; k` (relevance per mode).
    pub fn fact_in(&mut self, name: &str, ty: Tm, proof: Tm, origin: FactOrigin, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        // a fact over the irrelevant ghost bundle (§15.3) cannot be bound in
        // an exec body: it is given to the prover in each proof slot
        if !self.f.scope.ghost_locals.is_empty() && self.f.mode == super::Mode::Exec && !self.types_relevantly(&ty) {
            let saved = self.f.scope.clone();
            let d = self.depth();
            self.f.scope.hint_facts.push(super::scope::HintFact { ty: Val::new(ty, d), proof: Val::new(proof, d), name: "h_ghost", origin: FactOrigin::Requires });
            let _ = (name, origin, span);
            let body = k(self);
            self.f.scope = saved;
            return body;
        }
        // a proposition elaborated as a type (a law, a contract, an
        // assertion: `FnState::pure_facts`) must not embed its callees'
        // contract facts: a `let` there would put the callee's lemma into
        // the statement (a relevant position in proof mode), which changes
        // the statement's meaning for the lock and makes a law about `f`
        // depend on `f::ensures` — no §15.5 section could abstract it. The
        // facts are hints of the statement's proof slots instead.
        if self.f.pure_facts > 0 {
            let saved = self.f.scope.clone();
            let d = self.depth();
            let hint_name = match name {
                "h_ens" => "h_ens",
                "h_ref" => "h_ref",
                _ => "h_fact",
            };
            self.f.scope.hint_facts.push(super::scope::HintFact { ty: Val::new(ty, d), proof: Val::new(proof, d), name: hint_name, origin });
            let _ = span;
            let body = k(self);
            self.f.scope = saved;
            return body;
        }
        let saved = self.f.scope.clone();
        let rel = self.fact_rel();
        self.push_fact(name, &ty, Some(&proof), origin, span)?;
        let body = k(self);
        self.f.scope = saved;
        Ok(mk::let_(name, rel, ty, proof, body?))
    }

    /// Whether `ty` is a type in the current context, in a relevant
    /// position (it does not mention the irrelevant ghost bundle outside an
    /// irrelevant sub-position, §5.3).
    fn types_relevantly(&self, ty: &Tm) -> bool {
        let mut b = sandblaster_kernel::value::Budget { steps: self.opts.goal_budget };
        !matches!(self.env.infer(&self.f.scope.ctx, ty, &mut b), Err(e) if matches!(e.kind, sandblaster_kernel::api::KernelErrorKind::Relevance))
    }

    /// Whether a branching expression is elaborated in CPS (the
    /// continuation moves into every branch) rather than as a join: always
    /// with an early exit inside; also when it assigns outer locals (so the
    /// code after it sees each branch's values with its path condition,
    /// instead of projections of a stuck join), unless the continuation has
    /// already been duplicated [`CPS_LIMIT`] times on this path.
    pub fn use_cps(&self, e: &Expr) -> bool {
        if has_exit(e) {
            return true;
        }
        self.f.cps_depth < CPS_LIMIT && assigned_in(e).iter().any(|l| self.f.scope.locals.contains_key(l))
    }

    /// The join type of a branching expression (value type plus assigned
    /// outer locals).
    pub fn join_ty(&self, vty: &Ty, assigned: &[LocalId]) -> Ty {
        if assigned.is_empty() {
            return vty.clone();
        }
        let mut comps = Vec::new();
        if !vty.is_unit() && !vty.is_never() {
            comps.push(vty.clone());
        }
        for l in assigned {
            comps.push(self.local_decl(*l).ty.clone());
        }
        if comps.len() == 1 { comps.pop().unwrap() } else { Ty::Tuple(comps) }
    }

    /// The join value of a branch.
    fn join_value(&mut self, v: Val, vty: &Ty, assigned: &[LocalId], span: Span) -> R<Tm> {
        let d = self.depth();
        if assigned.is_empty() {
            return Ok(v.at(d));
        }
        let mut vals = Vec::new();
        let mut tys = Vec::new();
        if !vty.is_unit() && !vty.is_never() {
            vals.push(v.at(d));
            tys.push(self.ty(vty, span)?);
        }
        for l in assigned {
            vals.push(self.local_tm(*l, span)?);
            tys.push(self.ty(&self.local_decl(*l).ty, span)?);
        }
        if vals.len() == 1 {
            return Ok(vals.pop().unwrap());
        }
        self.tuple_val(tys, vals, span)
    }

    /// Runs `build` in join mode (see the module docs) and continues with
    /// `k` once.
    pub fn join(&mut self, e: &'a Expr, k: &mut K<'_, 'a>, build: &mut dyn FnMut(&mut Elab<'a>, &Answer, &mut K<'_, 'a>) -> R<Tm>) -> R<Tm> {
        let span = e.span;
        let assigned: Vec<LocalId> = assigned_in(e).into_iter().filter(|l| self.f.scope.locals.contains_key(l)).collect();
        let vty = e.ty.clone();
        let jt = self.join_ty(&vty, &assigned);
        let answer = Answer::Ty(jt.clone());
        let saved_answer = std::mem::replace(&mut self.f.answer, jt.clone());
        let assigned2 = assigned.clone();
        let vty2 = vty.clone();
        let jterm = build(self, &answer, &mut |s, v| s.join_value(v, &vty2, &assigned2, span));
        self.f.answer = saved_answer;
        let jterm = jterm?;
        // a pure value in a proof (lemma/law statements, scripts): used in
        // place, without a `let` (a smaller goal shape for the provers;
        // `let`s are transparent, so both forms are convertible)
        if assigned.is_empty() && self.f.mode == super::Mode::Proof {
            return self.cont(k, jterm);
        }
        let jty = self.ty(&jt, span)?;
        self.let_in("j", Rel::Rel, jty, jterm, &mut |s, lj| s.destructure_join(lj, &jt, &vty, &assigned, 0, span, k))
    }

    /// Binds the assigned locals from a join value (from component `i` on)
    /// and continues with the value.
    #[allow(clippy::too_many_arguments)]
    fn destructure_join(&mut self, lj: u32, jt: &Ty, vty: &Ty, assigned: &[LocalId], i: usize, span: Span, k: &mut K<'_, 'a>) -> R<Tm> {
        if assigned.is_empty() {
            let t = self.f.scope.var(lj);
            return self.cont(k, t);
        }
        let has_val = !vty.is_unit() && !vty.is_never();
        let ncomp = assigned.len() + usize::from(has_val);
        if ncomp == 1 {
            self.f.scope.locals.insert(assigned[0], lj);
            let u = self.unit_val();
            return self.cont(k, u);
        }
        let Ty::Tuple(comps) = jt else { return internal(span, "join type is not a tuple") };
        let (ind, params) = self.ind_of(jt, span)?;
        let first = usize::from(has_val);
        if i < assigned.len() {
            let l = assigned[i];
            let fty = self.ty(&comps[first + i], span)?;
            let pr = self.proj(ind, params, self.f.scope.var(lj), first + i, comps.len(), fty.clone());
            let name = self.local_decl(l).name.clone();
            return self.let_in(&name, Rel::Rel, fty, pr, &mut |s, lvl| {
                s.f.scope.locals.insert(l, lvl);
                s.destructure_join(lj, jt, vty, assigned, i + 1, span, k)
            });
        }
        if has_val {
            let fty = self.ty(&comps[0], span)?;
            let t = self.proj(ind, params, self.f.scope.var(lj), 0, comps.len(), fty);
            self.cont(k, t)
        } else {
            let u = self.unit_val();
            self.cont(k, u)
        }
    }

    fn if_expr(&mut self, e: &'a Expr, cond: &'a Expr, then: &'a Expr, els: Option<&'a Expr>, k: &mut K<'_, 'a>) -> R<Tm> {
        let span = e.span;
        let mut body = |s: &mut Elab<'a>, answer: &Answer, leaf: &mut K<'_, 'a>| -> R<Tm> {
            s.expr(cond, &mut |s, vc| {
                let c = vc.at(s.depth());
                s.if_then_else(c, answer, span, &mut |s, b| {
                    if b {
                        s.expr(then, leaf)
                    } else {
                        match els {
                            Some(x) => s.expr(x, leaf),
                            None => {
                                let u = s.unit_val();
                                s.cont(leaf, u)
                            }
                        }
                    }
                })
            })
        };
        if self.use_cps(e) {
            let answer = Answer::Ty(self.f.answer.clone());
            self.f.cps_depth += 1;
            let r = body(self, &answer, k);
            self.f.cps_depth -= 1;
            return r;
        }
        self.join(e, k, &mut body)
    }

    /// `a && b` ≡ `if a { b } else { false }`, `a || b` ≡ `if a { true }
    /// else { b }` (§3.3).
    fn short_circuit(&mut self, e: &'a Expr, a: &'a Expr, b: &'a Expr, and: bool, k: &mut K<'_, 'a>) -> R<Tm> {
        let span = e.span;
        // a chain of one operator is elaborated right-nested whatever its
        // parse: `a && b && c` parses as `(a && b) && c`, whose outer test
        // would branch on the inner chain's value — copied into the path
        // equation of every level (a term exponential in the length);
        // `a && (b && c)` branches on `a`, `b`, `c` in turn (the same order
        // of evaluation and the same value)
        //
        // (not in the body of an exec function: its term is what the code
        // generator prints, which keeps the source's nesting)
        //
        // Short chains (fewer than `FLAT_CHAIN` operands, a term of at most
        // 3^4 copies) keep their parse, as do the bodies of exec functions:
        // their term is what the code generator prints.
        let exec_body = self.f.mode == super::Mode::Exec && self.f.pure_facts == 0 && self.f.fdef.is_some_and(|f| f.kind == FnKind::Exec);
        let mut ops: Vec<&'a Expr> = Vec::new();
        chain_operands(a, and, &mut ops);
        chain_operands(b, and, &mut ops);
        let flat = !exec_body && ops.len() >= FLAT_CHAIN;
        if !flat {
            ops = vec![a, b];
        }
        let ops = &ops[..];
        let mut body = |s: &mut Elab<'a>, answer: &Answer, leaf: &mut K<'_, 'a>| -> R<Tm> { s.chain_step(ops, 0, and, answer, span, leaf) };
        if has_exit(e) {
            let answer = Answer::Ty(self.f.answer.clone());
            return body(self, &answer, k);
        }
        self.join(e, k, &mut body)
    }

    /// Operand `i` of a flattened `&&` (`and`) / `||` chain `ops` and the
    /// rest of the chain: `if ops[i] { rest } else { false }` for `&&`
    /// (`if ops[i] { true } else { rest }` for `||`); the last operand is
    /// the value.
    fn chain_step(&mut self, ops: &[&'a Expr], i: usize, and: bool, answer: &Answer, span: Span, leaf: &mut K<'_, 'a>) -> R<Tm> {
        if i + 1 >= ops.len() {
            return self.expr(ops[i], leaf);
        }
        self.expr(ops[i], &mut |s, va| {
            let c = va.at(s.depth());
            s.if_then_else(c, answer, span, &mut |s, taken| {
                if taken == and {
                    s.chain_step(ops, i + 1, and, answer, span, leaf)
                } else {
                    let t = s.bool_lit(!and);
                    s.cont(leaf, t)
                }
            })
        })
    }

    /// `x?` on `Option` (§3.3): `None` returns `None` from the function;
    /// `Some(v)` continues with `v`.
    fn try_(&mut self, x: &'a Expr, v: Val, k: &mut K<'_, 'a>, span: Span) -> R<Tm> {
        let Ty::Option(inner) = x.ty.peel_refs() else { return internal(span, "`?` on a non-Option") };
        let it = self.ty(inner, span)?;
        let Ty::Option(ret_inner) = self.f.ret.clone() else { return internal(span, "`?` in a function not returning Option") };
        let answer = Answer::Ty(self.f.answer.clone());
        let scrut = v.at(self.depth());
        self.dep_match(self.p.option, vec![it], scrut, &answer, span, &mut |s, ci, lvls| {
            if ci == 0 {
                let rt = s.ty(&ret_inner, span)?;
                Ok(mk::ctor(s.p.option, 0, vec![rt], vec![]))
            } else {
                let t = s.f.scope.var(lvls[0]);
                s.cont(k, t)
            }
        })
    }

    /// `unreachable!()`: `absurd(A, p)` with `p : Empty` proven from the
    /// path condition.
    pub fn unreachable(&mut self, span: Span) -> R<Tm> {
        let empty = mk::ind(self.p.empty, vec![]);
        let p = self.prove(ObligationKind::Unreachable, span, &empty, false)?;
        let a = self.answer_tm(&Answer::Ty(self.f.answer.clone()), span)?;
        Ok(Rc::new(Term::Absurd { ty: a, proof: p }))
    }

    // ------------------------------------------------------------------
    // blocks and statements
    // ------------------------------------------------------------------

    pub fn block(&mut self, b: &'a Block, k: &mut K<'_, 'a>) -> R<Tm> {
        self.stmts(b, 0, k)
    }

    fn stmts(&mut self, b: &'a Block, i: usize, k: &mut K<'_, 'a>) -> R<Tm> {
        let Some(s) = b.stmts.get(i) else {
            return match &b.tail {
                Some(t) => self.expr(t, k),
                None => {
                    let u = self.unit_val();
                    self.cont(k, u)
                }
            };
        };
        let span = s.span;
        match &s.kind {
            StmtKind::Let { pat, init, els: None } => self.expr(init, &mut |me, v| me.bind_irrefutable(pat, v, span, &mut |me| me.stmts(b, i + 1, k))),
            StmtKind::Let { pat, init, els: Some(els) } => self.expr(init, &mut |me, v| me.let_else(pat, v, els, span, &mut |me| me.stmts(b, i + 1, k))),
            StmtKind::Expr(e) => self.expr(e, &mut |me, v| me.discard(&e.ty, v, span, &mut |me| me.stmts(b, i + 1, k))),
            // the invariant facts of values projected in place indices
            // (elaborated in a pure context, §15.3) are bound first
            StmtKind::Assign { place, value } => self.prebind_inv_facts(&place_indices(place), &[], span, &mut |me| me.expr(value, &mut |me, v| me.assign(place, v, span, &mut |me| me.stmts(b, i + 1, k)))),
            StmtKind::CompoundAssign { op, place, value } => self.prebind_inv_facts(&place_indices(place), &[], span, &mut |me| {
                me.expr(value, &mut |me, v| {
                    let cur = me.place_value(place, span)?;
                    let d = me.depth();
                    let nv = me.binop(*op, &place.ty, &value.ty, cur, v.at(d), span)?;
                    let nv = Val::new(nv, me.depth());
                    me.assign(place, nv, span, &mut |me| me.stmts(b, i + 1, k))
                })
            }),
            StmtKind::CopyFromSlice { dst, range, src } => {
                let mut list: Vec<&'a Expr> = Vec::new();
                if let Some((lo, hi)) = range {
                    list.extend(lo.iter());
                    list.extend(hi.iter());
                }
                list.push(src);
                self.exprs_ref(&list, &mut |me, vs| {
                    let d = me.depth();
                    let mut idx = 0;
                    let (lo, hi) = match range {
                        Some((lo, hi)) => {
                            let l = lo.as_ref().map(|_| {
                                idx += 1;
                                vs[idx - 1].at(d)
                            });
                            let h = hi.as_ref().map(|_| {
                                idx += 1;
                                vs[idx - 1].at(d)
                            });
                            (l, h)
                        }
                        None => (None, None),
                    };
                    let src_t = vs[idx].at(d);
                    me.copy_from_slice(*dst, lo, hi, src_t, span, &mut |me| me.stmts(b, i + 1, k))
                })
            }
            // test-only exec-only elaboration: a block about ghost items it
            // does not elaborate is left out (`names_skipped_ghost_item`)
            StmtKind::Proof(steps) if self.opts.exec_only && self.names_skipped_ghost_item(steps) => self.stmts(b, i + 1, k),
            // the invariant facts of values projected in the steps'
            // propositions (§15.3) are bound first
            StmtKind::Proof(steps) => self.prebind_inv_facts(&[], steps, span, &mut |me| me.exec_proof(steps, span, &mut |me| me.stmts(b, i + 1, k))),
        }
    }

    /// Whether a `proof!` block names an item the test-only exec-only mode
    /// ([`super::Options::exec_only`]) does not elaborate: a spec function,
    /// lemma, law or proof, or a ghost constant. Such a block is reasoning
    /// for the ghost layer (in practice a step of a refinement or law
    /// proof, whose lemma's preconditions are the callees' refinements,
    /// which exec-only does not establish either), and it is erased from
    /// the program anyway (`lower`), so exec-only leaves it out, as it
    /// leaves out the items it names. This only drops facts:
    /// an exec obligation that needed one is reported unproven, and
    /// exec-only output is never a verification (`Verification::exec_only`).
    /// A block naming only exec items and prelude lemmas is elaborated as
    /// usual.
    fn names_skipped_ghost_item(&self, steps: &[ScriptStmt]) -> bool {
        struct Refs<'k> {
            krate: &'k Crate,
            hit: bool,
        }
        impl Refs<'_> {
            fn note(&mut self, id: ItemId) {
                self.hit |= match &self.krate.item(id).kind {
                    // (a prelude lemma is a synthetic ghost lemma item that
                    // exec-only elaboration still has: its kernel global)
                    ItemKind::Fn(f) => f.kind != FnKind::Exec && crate::resolve::prelude_lemma_kernel_name(&self.krate.item(id).path).is_none(),
                    ItemKind::Const(_) => self.krate.item(id).ghost,
                    _ => false,
                };
            }
        }
        impl Visitor for Refs<'_> {
            fn expr(&mut self, e: &Expr) {
                match &e.kind {
                    ExprKind::Call { callee: Callee::Item(id, _), .. } | ExprKind::Const(id) => self.note(*id),
                    _ => {}
                }
                visit::walk_expr(self, e);
            }
            fn script(&mut self, s: &ScriptStmt) {
                match &s.kind {
                    ScriptKind::Unfold(UnfoldTarget::Item(id)) => self.note(*id),
                    ScriptKind::Using(ids) => ids.iter().for_each(|id| self.note(*id)),
                    ScriptKind::Unfolding(ts) => ts.iter().for_each(|t| {
                        if let UnfoldTarget::Item(id) = t {
                            self.note(*id)
                        }
                    }),
                    _ => {}
                }
                visit::walk_script(self, s);
            }
        }
        let mut r = Refs { krate: self.krate, hit: false };
        steps.iter().for_each(|s| r.script(s));
        r.hit
    }

    /// An expression statement: its value is bound to `_` (so every proof
    /// slot it contains is kept for the kernel) unless it is trivial.
    fn discard(&mut self, ty: &Ty, v: Val, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let trivial = ty.is_unit() || ty.is_never() || v.is_trivial() || matches!(&*v.tm, Term::Ctor { args, .. } if args.is_empty());
        if trivial {
            return k(self);
        }
        let t = self.ty(ty, span)?;
        let d = self.depth();
        self.let_in("_", Rel::Rel, t, v.at(d), &mut |me, _| k(me))
    }

    /// Binds a HIR local to a value: aliases variables, else a `let`.
    /// Slice-typed locals get their `ISIZE_MAX` bound as a fact.
    pub fn bind_local(&mut self, l: LocalId, v: Val, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let d = self.depth();
        if let Term::Var(sandblaster_kernel::term::Idx(i)) = &*v.at(d) {
            self.f.scope.locals.insert(l, d - 1 - *i);
            // a value with an invariant: its facts (§15.3; once per value)
            let lty = self.local_decl(l).ty.clone();
            return self.with_inv_facts(&v, &lty, span, k);
        }
        let decl = self.local_decl(l);
        // a ghost `let` over the irrelevant ghost bundle (§15.3) cannot be a
        // relevant `let` of the exec body: the local stands for its value
        if decl.ghost && !self.f.scope.ghost_locals.is_empty() && self.f.mode == super::Mode::Exec {
            let mut b = sandblaster_kernel::value::Budget { steps: self.opts.goal_budget };
            if matches!(self.env.infer(&self.f.scope.ctx, &v.at(d), &mut b), Err(e) if matches!(e.kind, sandblaster_kernel::api::KernelErrorKind::Relevance)) {
                self.f.scope.ghost_locals.insert(l, v);
                return k(self);
            }
        }
        let ty = self.ty(&decl.ty, span)?;
        let name = decl.name.clone();
        let slice_elem = match decl.ty.peel_refs() {
            Ty::Slice(e) => Some((**e).clone()),
            _ => None,
        };
        let lty = decl.ty.clone();
        self.let_in(&name, Rel::Rel, ty, v.at(d), &mut |me, lvl| {
            me.f.scope.locals.insert(l, lvl);
            match &slice_elem {
                Some(e) => me.slice_bound_fact(e, lvl, span, k),
                None => {
                    let vl = Val::new(me.f.scope.var(lvl), me.depth());
                    me.with_inv_facts(&vl, &lty, span, k)
                }
            }
        })
    }

    /// `slice::ok_bound T s : len(s) ≤ ISIZE_MAX` as a fact (§3.2, §5.8).
    pub fn slice_bound_fact(&mut self, elem: &Ty, lvl: u32, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let et = self.ty(elem, span)?;
        let s = self.f.scope.var(lvl);
        let ty = self.holds(self.p0(PrimOp::Le(Width::Int), vec![self.p0(PrimOp::Cast { from: Width::Usize, to: Width::Int }, vec![mk::fst(s.clone())]), mk::global(self.p.g("ISIZE_MAX"))]));
        let pf = mk::apps(mk::global(self.p.g("slice::ok_bound")), [(Rel::Rel, et), (Rel::Rel, s)]);
        self.fact_in("h_ok", ty, pf, FactOrigin::TypeBound, span, k)
    }

    /// The current value of a place.
    fn place_value(&mut self, p: &'a Place, span: Span) -> R<Tm> {
        let mut t = self.local_tm(p.local, span)?;
        let mut ty = self.local_decl(p.local).ty.clone();
        for pr in &p.projs {
            match pr {
                Proj::Field { index, .. } => {
                    t = self.field(&ty, t, *index as usize, span)?;
                    ty = self.proj_ty(&ty, *index as usize, span)?;
                }
                Proj::Index(ix) => {
                    let i = self.pure_value(ix)?;
                    t = self.index(&ty, t, i, span)?;
                    ty = match ty.peel_refs() {
                        Ty::Array(e, _) => (**e).clone(),
                        _ => return internal(span, "place index on a non-array"),
                    };
                }
            }
        }
        Ok(t)
    }

    fn proj_ty(&self, t: &Ty, index: usize, span: Span) -> R<Ty> {
        let ftys = self.ctor_field_tys(t.peel_refs(), 0, span)?;
        ftys.get(index).cloned().ok_or_else(|| ElabError { span, msg: "field index".into(), kind: ErrKind::Internal })
    }

    /// Elaborates an expression that must not bind anything (place
    /// indices): its value at the current depth.
    fn pure_value(&mut self, e: &'a Expr) -> R<Tm> {
        let d = self.depth();
        let mut out = None;
        let _ = self.in_pure(|s| {
            s.expr(e, &mut |s, v| {
                out = Some(v.clone());
                Ok(s.unit_val())
            })
        })?;
        let v = out.ok_or_else(|| ElabError { span: e.span, msg: "place index diverges".into(), kind: ErrKind::Unsupported })?;
        if v.depth != d {
            return unsupported(e.span, "place indices must be simple expressions (no blocks or branches)");
        }
        Ok(v.at(d))
    }

    /// `place = v` (§3.3): SSA for locals; `array::set` and constructor
    /// rebuilding for element/field places.
    fn assign(&mut self, place: &'a Place, v: Val, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let root_ty = self.local_decl(place.local).ty.clone();
        let root = self.local_tm(place.local, span)?;
        let d = self.depth();
        let nv = self.update(&root_ty, root, &place.projs, v.at(d), span)?;
        let decl = self.local_decl(place.local);
        let ty = self.ty(&decl.ty, span)?;
        let name = decl.name.clone();
        let slice_elem = match decl.ty.peel_refs() {
            Ty::Slice(e) => Some((**e).clone()),
            _ => None,
        };
        let l = place.local;
        self.let_in(&name, Rel::Rel, ty, nv, &mut |me, lvl| {
            me.f.scope.locals.insert(l, lvl);
            match &slice_elem {
                Some(e) => me.slice_bound_fact(e, lvl, span, k),
                None => k(me),
            }
        })
    }

    /// `x` with the value at `projs` replaced by `v`.
    fn update(&mut self, ty: &Ty, x: Tm, projs: &'a [Proj], v: Tm, span: Span) -> R<Tm> {
        let Some((first, rest)) = projs.split_first() else { return Ok(v) };
        match first {
            Proj::Field { index, .. } => {
                let bt = ty.peel_refs();
                let (ind, params) = self.ind_of(bt, span)?;
                let ftys = self.ctor_field_tys(bt, 0, span)?;
                let mut args = Vec::new();
                for (k, fty) in ftys.iter().enumerate() {
                    let ft = self.ty(fty, span)?;
                    let pk = self.proj(ind, params.clone(), x.clone(), k, ftys.len(), ft);
                    args.push(if k == *index as usize { self.update(fty, pk, rest, v.clone(), span)? } else { pk });
                }
                // SSA field assignment rebuilds the value: its invariant is
                // an obligation here (§15.3)
                let owner = match bt {
                    Ty::Adt(id, _) => Some(*id),
                    _ => None,
                };
                self.ctor_with_invariants(ind, 0, params, args, owner, span)
            }
            Proj::Index(ix) => {
                let Ty::Array(e, n) = ty.peel_refs() else { return internal(span, "element assignment on a non-array") };
                let i = self.pure_value(ix)?;
                let et = self.ty(e, span)?;
                let goal = self.holds(self.p0(PrimOp::Lt(Width::Usize), vec![i.clone(), mk::lit(Width::Usize, *n)]));
                let pf = self.prove(ObligationKind::IndexBounds, span, &goal, false)?;
                let inner = if rest.is_empty() {
                    v
                } else {
                    let cur = mk::apps(mk::global(self.p.g("array::index")), [(Rel::Rel, et.clone()), (Rel::Rel, mk::lit(Width::Usize, *n)), (Rel::Rel, x.clone()), (Rel::Rel, i.clone()), (Rel::Irr, pf.clone())]);
                    self.update(e, cur, rest, v, span)?
                };
                Ok(mk::apps(mk::global(self.p.g("array::set")), [(Rel::Rel, et), (Rel::Rel, mk::lit(Width::Usize, *n)), (Rel::Rel, x), (Rel::Rel, i), (Rel::Rel, inner), (Rel::Irr, pf)]))
            }
        }
    }

    /// `dst[lo..hi].copy_from_slice(src)` on an array local (§3.3):
    /// `array::copy_range` with obligations `lo ≤ hi`, `hi ≤ N`,
    /// `hi − lo = src.len()`.
    #[allow(clippy::too_many_arguments)]
    fn copy_from_slice(&mut self, dst: LocalId, lo: Option<Tm>, hi: Option<Tm>, src: Tm, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let decl = self.local_decl(dst);
        let Ty::Array(e, n) = decl.ty.clone() else { return internal(span, "copy_from_slice on a non-array") };
        let et = self.ty(&e, span)?;
        let a = self.local_tm(dst, span)?;
        let lo = lo.unwrap_or_else(|| mk::lit(Width::Usize, 0u8));
        let hi = hi.unwrap_or_else(|| mk::lit(Width::Usize, n));
        let le = |me: &Self, x: Tm, y: Tm| me.holds(me.p0(PrimOp::Le(Width::Usize), vec![x, y]));
        let g0 = le(self, lo.clone(), hi.clone());
        let h0 = self.prove(ObligationKind::SliceRange, span, &g0, false)?;
        let g1 = le(self, hi.clone(), mk::lit(Width::Usize, n));
        let h1 = self.prove(ObligationKind::SliceRange, span, &g1, false)?;
        let sub = mk::prim(PrimOp::Sub(Width::Usize), vec![hi.clone(), lo.clone()], vec![h0.clone()]);
        let g2 = self.holds(self.p0(PrimOp::Eq(Width::Usize), vec![sub, mk::fst(src.clone())]));
        let h2 = self.prove(ObligationKind::SliceRange, span, &g2, false)?;
        let nv = mk::apps(
            mk::global(self.sem.copy_range),
            [(Rel::Rel, et), (Rel::Rel, mk::lit(Width::Usize, n)), (Rel::Rel, a), (Rel::Rel, lo), (Rel::Rel, hi), (Rel::Rel, src), (Rel::Irr, h0), (Rel::Irr, h1), (Rel::Irr, h2)],
        );
        let ty = self.ty(&decl.ty, span)?;
        let name = decl.name.clone();
        self.let_in(&name, Rel::Rel, ty, nv, &mut |me, lvl| {
            me.f.scope.locals.insert(dst, lvl);
            k(me)
        })
    }

    // ------------------------------------------------------------------
    // intrinsics (§9.2)
    // ------------------------------------------------------------------

    fn intrinsic_call(&mut self, i: crate::intrinsics::IntrinsicId, imms: &[i64], args: Vec<Tm>, span: Span) -> R<Tm> {
        let info = crate::intrinsics::get(i);
        let name = format!("{}::{}", info.arch.name(), info.name);
        let Some(g) = self.sem.intrinsics.get(&name).copied() else {
            return Err(ElabError { span, msg: format!("intrinsic `{}` has no core model in the target semantics library (`sandblaster/targets/core`)", info.name), kind: ErrKind::Deferred });
        };
        // immediates first (relevant `U32`), each with its range proofs
        // (`lo ≤ N` when `lo > 0`, then `N ≤ hi`; by evaluation for literals)
        let mut all: Vec<(Rel, Tm)> = Vec::new();
        for (v, imm) in imms.iter().zip(&info.imms) {
            all.push((Rel::Rel, mk::lit(Width::U32, (*v).max(0) as u64)));
            let refl = mk::refl(mk::bool_ty(self.p.bool_), self.bool_lit(true));
            if imm.lo > 0 {
                all.push((Rel::Irr, refl.clone()));
            }
            all.push((Rel::Irr, refl));
        }
        all.extend(args.into_iter().map(|a| (Rel::Rel, a)));
        Ok(mk::apps(mk::global(g), all))
    }

    /// Index of the unit-typed local-free check: `peel_coerce` is used by
    /// the measure inference.
    pub fn peel(e: &Expr) -> &Expr {
        peel_coerce(e)
    }
}

/// The index expressions of a place (`a[i].f[j]`): elaborated in a pure
/// context, so the invariant facts of the values they project are bound
/// before the statement (`Elab::prebind_inv_facts`, §15.3).
fn place_indices(place: &Place) -> Vec<&Expr> {
    place.projs.iter().filter_map(|p| if let Proj::Index(ix) = p { Some(ix) } else { None }).collect()
}
