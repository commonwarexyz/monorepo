//! Early exits in spec functions (§15 S5; SEMANTICS.md §13.11): `?` and
//! `return` are sugar, removed here right after the body is typed, so every
//! later stage (elaboration, examples, mutation, de-elaboration) sees a
//! pure expression.
//!
//! The rewriting moves "the rest of the function" into the branches that
//! continue (the continuation `k`), and makes a branch that exits end with
//! its value:
//!
//! * `let p = e?; rest` ⇒ `match e { Some(p) => rest, None => None }` (the
//!   function returns `Option`, checked when the body is typed);
//! * a branch value `e?` ⇒ `match e { Some(x) => k(x), None => None }`;
//! * `return v` ⇒ `v` (the continuation is dropped);
//! * `if c { .. return a; } rest` ⇒ `if c { .. a } else { rest }`, and a
//!   `let p = match s { .. => return v, q => w };` pushes `let p = w; rest`
//!   into the arms that continue (likewise `if`/`else` and blocks).
//!
//! An exit anywhere else (inside a call's argument, a condition, a
//! scrutinee or a guard) is an error: write it as a `let` first.

use crate::diag::{DiagKind, Diagnostic};
use crate::visit::Visitor;
use crate::hir::*;
use crate::span::Span;

use super::expr::Cx;

/// Whether `e` contains `?` or `return` (at any depth).
pub fn has_exit(e: &Expr) -> bool {
    struct V(bool);
    impl Visitor for V {
        fn expr(&mut self, e: &Expr) {
            if matches!(e.kind, ExprKind::Return(_) | ExprKind::Try(_)) {
                self.0 = true;
            }
            if !self.0 {
                crate::visit::walk_expr(self, e);
            }
        }
    }
    let mut v = V(false);
    v.expr(e);
    v.0
}

/// The continuation of a branch value: what the rest of the function does
/// with it.
type K<'k> = &'k dyn Fn(&mut Cx<'_, '_>, Expr) -> Expr;

impl<'c, 'a> Cx<'c, 'a> {
    /// The body of a spec function returning `ret`, with its `?` and
    /// `return` removed (see the module docs). A body without exits is
    /// returned unchanged.
    pub fn desugar_exits(&mut self, body: Expr, ret: &Ty) -> Expr {
        if !has_exit(&body) {
            return body;
        }
        let ret = ret.clone();
        self.exit_bind(body, &ret, &|_, v| v)
    }

    /// `k(e)`, where `e` may exit: the exits of `e`'s branches end the
    /// function, the other branch values go to `k`.
    fn exit_bind(&mut self, e: Expr, ret: &Ty, k: K<'_>) -> Expr {
        if !has_exit(&e) {
            return k(self, e);
        }
        let span = e.span;
        match e.kind {
            ExprKind::Return(v) => match v {
                Some(v) => self.exit_bind(*v, ret, &|_, x| x),
                None => Expr::new(ExprKind::Tuple(vec![]), ret.clone(), span),
            },
            ExprKind::Try(inner) => {
                if has_exit(&inner) {
                    return self.exit_error(span, "`?` inside the operand of `?`");
                }
                let Ty::Option(t) = &inner.ty else { return self.exit_error(span, "`?` on a value that is not an `Option`") };
                let t = (**t).clone();
                let x = self.new_local("value", t.clone(), false, true, span);
                let bind = Pat { kind: PatKind::Binding { local: x, mode: BindingMode::ByValue, sub: None }, ty: t.clone(), span };
                let value = Expr::new(ExprKind::Local(x), t.clone(), span);
                let cont = k(self, value);
                self.some_or_none(*inner, t, bind, cont, ret, span)
            }
            ExprKind::Block(b) => self.exit_seq(b.stmts, 0, b.tail.map(|t| *t), ret, span, k),
            ExprKind::If { cond, then, els } => {
                if has_exit(&cond) {
                    return self.exit_error(cond.span, "an exit in the condition of an `if`");
                }
                let then = self.exit_bind(*then, ret, k);
                let els = match els {
                    Some(e) => self.exit_bind(*e, ret, k),
                    None => k(self, Expr::new(ExprKind::Tuple(vec![]), Ty::unit(), span)),
                };
                Expr::new(ExprKind::If { cond, then: Box::new(then), els: Some(Box::new(els)) }, ret.clone(), span)
            }
            ExprKind::Match { scrut, arms, source } => {
                if has_exit(&scrut) || arms.iter().any(|a| a.guard.as_ref().is_some_and(has_exit)) {
                    return self.exit_error(span, "an exit in the scrutinee or a guard of a `match`");
                }
                let arms = arms.into_iter().map(|a| Arm { pat: a.pat, guard: a.guard, body: self.exit_bind(a.body, ret, k), span: a.span }).collect();
                Expr::new(ExprKind::Match { scrut, arms, source }, ret.clone(), span)
            }
            _ => self.exit_error(span, "`?` or `return` inside a larger expression"),
        }
    }

    /// The statements `stmts[i..]` and `tail` of a block whose value goes
    /// to `k`.
    fn exit_seq(&mut self, stmts: Vec<Stmt>, i: usize, tail: Option<Expr>, ret: &Ty, span: Span, k: K<'_>) -> Expr {
        // the statements up to the first one that exits stay as they are
        let j = (i..stmts.len()).find(|&j| stmt_exits(&stmts[j])).unwrap_or(stmts.len());
        let prefix: Vec<Stmt> = stmts[i..j].to_vec();
        let rest = if j == stmts.len() {
            match tail {
                Some(t) => self.exit_bind(t, ret, k),
                None => k(self, Expr::new(ExprKind::Tuple(vec![]), Ty::unit(), span)),
            }
        } else {
            let s = stmts[j].clone();
            let sspan = s.span;
            match s.kind {
                // `let p = e?; rest` ⇒ `match e { Some(p) => rest, None => None }`
                StmtKind::Let { pat, init: Expr { kind: ExprKind::Try(inner), .. }, els: None } if !has_exit(&inner) && matches!(inner.ty, Ty::Option(_)) => {
                    let Ty::Option(t) = &inner.ty else { unreachable!() };
                    let t = (**t).clone();
                    let rest = self.exit_seq(stmts.clone(), j + 1, tail.clone(), ret, span, k);
                    self.some_or_none(*inner, t, pat, rest, ret, sspan)
                }
                StmtKind::Let { pat, init, els: None } => {
                    let stmts2 = stmts.clone();
                    let tail2 = tail.clone();
                    let cont = move |cx: &mut Cx<'_, '_>, v: Expr| -> Expr {
                        let body = cx.exit_seq(stmts2.clone(), j + 1, tail2.clone(), ret, span, k);
                        let let_ = Stmt { kind: StmtKind::Let { pat: pat.clone(), init: v, els: None }, span: sspan };
                        Expr::new(ExprKind::Block(Block { stmts: vec![let_], tail: Some(Box::new(body)), span }), ret.clone(), span)
                    };
                    self.exit_bind(init, ret, &cont)
                }
                StmtKind::Expr(e) => {
                    let stmts2 = stmts.clone();
                    let tail2 = tail.clone();
                    let cont = move |cx: &mut Cx<'_, '_>, _v: Expr| -> Expr { cx.exit_seq(stmts2.clone(), j + 1, tail2.clone(), ret, span, k) };
                    self.exit_bind(e, ret, &cont)
                }
                StmtKind::Let { pat, init, els: Some(b) } => {
                    // `let p = e else { .. return v };` ⇒ `match e { p => rest, _ => v }`
                    if has_exit(&init) {
                        return self.exit_error(init.span, "an exit in the initializer of a `let … else`");
                    }
                    let body = self.exit_seq(stmts.clone(), j + 1, tail.clone(), ret, span, k);
                    let bspan = b.span;
                    let els = self.exit_bind(Expr::new(ExprKind::Block(b), Ty::Never, bspan), ret, &|_, v| v);
                    let wild = Pat { kind: PatKind::Wild, ty: pat.ty.clone(), span: bspan };
                    let arms = vec![Arm { pat, guard: None, body, span: sspan }, Arm { pat: wild, guard: None, body: els, span: bspan }];
                    Expr::new(ExprKind::Match { scrut: Box::new(init), arms, source: MatchSource::IfLet }, ret.clone(), sspan)
                }
                _ => self.exit_error(sspan, "an exit in this statement"),
            }
        };
        if prefix.is_empty() {
            return rest;
        }
        let ty = rest.ty.clone();
        Expr::new(ExprKind::Block(Block { stmts: prefix, tail: Some(Box::new(rest)), span }), ty, span)
    }

    /// `match inner { Some(bind) => cont, None => None }`.
    fn some_or_none(&mut self, inner: Expr, t: Ty, bind: Pat, cont: Expr, ret: &Ty, span: Span) -> Expr {
        let opt = Ty::option(t.clone());
        let some = Pat { kind: PatKind::Ctor { ctor: Ctor::Some, ty_args: vec![t.clone()], fields: vec![(0, bind)] }, ty: opt.clone(), span };
        let none_p = Pat { kind: PatKind::Ctor { ctor: Ctor::None, ty_args: vec![t], fields: vec![] }, ty: opt, span };
        let ret_inner = match ret {
            Ty::Option(r) => (**r).clone(),
            _ => Ty::Error,
        };
        let none_v = Expr::new(ExprKind::Adt { ctor: Ctor::None, ty_args: vec![ret_inner], fields: vec![], base: None }, ret.clone(), span);
        let arms = vec![Arm { pat: some, guard: None, body: cont, span }, Arm { pat: none_p, guard: None, body: none_v, span }];
        Expr::new(ExprKind::Match { scrut: Box::new(inner), arms, source: MatchSource::Match }, ret.clone(), span)
    }

    fn exit_error(&mut self, span: Span, what: &str) -> Expr {
        self.push(
            Diagnostic::error(DiagKind::Unsupported, span, format!("{what} is not supported in a spec function"))
                .note("in spec functions, `?` and `return` may end a `let` initializer or a branch (`let p = e?;`, `if c { return v; }`, `_ => return None`); bind the value with a `let` first (SEMANTICS.md §13.11)"),
        );
        Expr::new(ExprKind::Unreachable, Ty::Error, span)
    }
}

/// Whether a statement contains an exit.
fn stmt_exits(s: &Stmt) -> bool {
    match &s.kind {
        StmtKind::Let { init, els, .. } => has_exit(init) || els.as_ref().is_some_and(|b| has_exit(&Expr::new(ExprKind::Block(b.clone()), Ty::Never, b.span))),
        StmtKind::Expr(e) => has_exit(e),
        _ => false,
    }
}
