#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;

use rustc_errors::DiagDecorator;
use rustc_hir::{Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass, LintContext};

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects a `Supervisor::child` call on a temporary `Supervisor::child`, such as
    /// `context.child("a").child("b")`, including chains that pass through
    /// `with_attribute`, `shared` or `dedicated`. Calls must resolve to the traits in
    /// `commonware_runtime`.
    ///
    /// ### Why is this bad?
    ///
    /// Dropping a context closes its node and every context derived from it. The
    /// temporary parent is dropped at the end of the statement, so the child it
    /// returns is already closed: anything spawned from it is aborted at once.
    ///
    /// ### Known problems
    ///
    /// Like `borrowed_child_context`, the lint also rejects chains that happen to
    /// work: a closed context still serves metrics, storage and time, and a spawn
    /// awaited in the same statement finishes before the parent is dropped. Bind
    /// the parent in those too. The lint misses a parent moved into the chain,
    /// as in `context.with_attribute(..).child("b")`, and chains produced by a macro.
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
    "child of a temporary parent context"
}

impl<'tcx> LateLintPass<'tcx> for TemporaryParentContext {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if expr.span.from_expansion() || !is_runtime_method(cx, expr, "Supervisor", "child") {
            return;
        }
        let ExprKind::MethodCall(_, receiver, ..) = expr.kind else {
            return;
        };
        if let Some(parent) = child_call(cx, receiver) {
            cx.emit_span_lint(TEMPORARY_PARENT_CONTEXT, parent.span, DiagDecorator(|diag| {
                diag.primary_message("child of a temporary parent context");
                diag.help(
                    "the temporary parent is dropped at the end of the statement, which closes the child, so bind the parent context first",
                );
            }));
        }
    }
}

/// Follows `expr` through methods that return the context they consume and returns
/// the `Supervisor::child` call it reaches, if any.
fn child_call<'tcx>(cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) -> Option<&'tcx Expr<'tcx>> {
    let mut current = expr;
    while let ExprKind::MethodCall(_, receiver, ..) = current.kind {
        if current.span.from_expansion() {
            return None;
        }
        if is_runtime_method(cx, current, "Supervisor", "child") {
            return Some(current);
        }
        if !keeps_node(cx, current) {
            return None;
        }
        current = receiver;
    }
    None
}

/// Returns whether `expr` calls a runtime method that returns the context it consumed.
fn keeps_node(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    is_runtime_method(cx, expr, "Supervisor", "with_attribute")
        || is_runtime_method(cx, expr, "Spawner", "shared")
        || is_runtime_method(cx, expr, "Spawner", "dedicated")
}

fn is_runtime_method(
    cx: &LateContext<'_>,
    expr: &Expr<'_>,
    trait_name: &str,
    method_name: &str,
) -> bool {
    let Some(method) = cx.typeck_results().type_dependent_def_id(expr.hir_id) else {
        return false;
    };
    if cx.tcx.item_name(method).as_str() != method_name {
        return false;
    }
    let Some(trait_id) = cx.tcx.trait_of_assoc(method) else {
        return false;
    };
    cx.tcx.crate_name(trait_id.krate).as_str() == "commonware_runtime"
        && cx.tcx.item_name(trait_id).as_str() == trait_name
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
