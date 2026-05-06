#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_hir;
extern crate rustc_span;

use rustc_hir::{BorrowKind, Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_span::{Span, Symbol};

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects borrows of temporary child contexts, such as
    /// `&context.child("worker")` and `&mut self.context.child("worker")`.
    ///
    /// ### Why is this bad?
    ///
    /// The borrowed temporary is fragile, hard to audit, and can hide whether
    /// the callee needs a child context or could take the parent context.
    ///
    /// ### Example
    ///
    /// ```rust
    /// takes_context(&context.child("worker"));
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust
    /// let worker_context = context.child("worker");
    /// takes_context(&worker_context);
    /// ```
    pub BORROWED_CHILD_CONTEXT,
    Deny,
    "borrowed temporary child context"
}

impl<'tcx> LateLintPass<'tcx> for BorrowedChildContext {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if expr.span.from_expansion() {
            return;
        }

        let ExprKind::AddrOf(BorrowKind::Ref, _, borrowed) = expr.kind else {
            return;
        };

        if let Some(span) = first_child_call(borrowed) {
            cx.span_lint(BORROWED_CHILD_CONTEXT, span, |diag| {
                diag.primary_message("borrowed temporary child context");
                diag.span_help(
                    expr.span,
                    "bind the child context before borrowing, or pass the parent context",
                );
            });
        }
    }
}

fn first_child_call(expr: &Expr<'_>) -> Option<Span> {
    let child = Symbol::intern("child");
    let mut current = expr;

    while let ExprKind::MethodCall(segment, receiver, ..) = current.kind {
        if segment.ident.name == child {
            return Some(current.span);
        }
        current = receiver;
    }

    None
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
