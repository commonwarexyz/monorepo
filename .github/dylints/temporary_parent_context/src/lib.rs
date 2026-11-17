#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_span;

use rustc_errors::DiagDecorator;
use rustc_hir::{Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_span::Span;

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects child contexts derived from temporary parent contexts, including
    /// chains with methods such as `with_attribute`, `shared`, `dedicated`, or `clone`.
    ///
    /// ### Why is this bad?
    ///
    /// The temporary parent is dropped at the end of the statement, which closes
    /// it and every context derived from it. Tasks spawned below it are aborted.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let worker = context.child("service").child("worker");
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust
    /// let service = context.child("service");
    /// let worker = service.child("worker");
    /// ```
    pub TEMPORARY_PARENT_CONTEXT,
    Deny,
    "temporary parent context"
}

impl<'tcx> LateLintPass<'tcx> for TemporaryParentContext {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if expr.span.from_expansion() {
            return;
        }

        let ExprKind::MethodCall(_, receiver, ..) = expr.kind else {
            return;
        };
        if !is_supervisor_child(cx, expr) {
            return;
        }

        if let Some(span) = first_child_call(cx, receiver) {
            cx.emit_span_lint(TEMPORARY_PARENT_CONTEXT, span, DiagDecorator(|diag| {
                diag.primary_message("temporary parent context");
                diag.help(
                    "the temporary parent is dropped at the end of the statement, which closes it and every context derived from it, so bind the parent context first",
                );
            }));
        }
    }
}

fn first_child_call(cx: &LateContext<'_>, expr: &Expr<'_>) -> Option<Span> {
    let mut current = expr;

    while let ExprKind::MethodCall(_, receiver, ..) = current.kind {
        if current.span.from_expansion() {
            return None;
        }
        if is_supervisor_child(cx, current) {
            return Some(current.span);
        }
        current = receiver;
    }

    None
}

fn is_supervisor_child(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let Some(method) = cx.typeck_results().type_dependent_def_id(expr.hir_id) else {
        return false;
    };
    if cx.tcx.item_name(method).as_str() != "child" {
        return false;
    }
    let Some(trait_id) = cx.tcx.trait_of_assoc(method) else {
        return false;
    };
    cx.tcx.crate_name(trait_id.krate).as_str() == "commonware_runtime"
        && cx.tcx.item_name(trait_id).as_str() == "Supervisor"
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
