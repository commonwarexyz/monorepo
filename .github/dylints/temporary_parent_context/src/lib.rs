#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;

use rustc_errors::DiagDecorator;
use rustc_hir::{Expr, ExprKind, Node};
use rustc_lint::{LateContext, LateLintPass, LintContext};

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects a `Spawner::spawn` on a `Supervisor::child` of a temporary
    /// `Supervisor::child` whose handle goes unused in its statement: discarded, bound
    /// with `let`, or returned from the enclosing block, closure, or function.
    /// The chain may pass through `with_attribute`, `shared` and `dedicated`.
    /// Calls must resolve to the traits in `commonware_runtime`.
    ///
    /// ### Why is this bad?
    ///
    /// The temporary parent is dropped at the end of the statement or tail
    /// expression, which closes it and aborts the spawned task before anything
    /// can wait for it.
    ///
    /// ### Known problems
    ///
    /// The lint stays silent when the handle is used in the same statement
    /// (awaited, passed to a function, pushed into a collection, or wrapped with
    /// `abort_on_drop`), since some of those uses keep the parent alive long
    /// enough. It also misses a parent moved into the chain, as in
    /// `context.with_attribute(..).child("b").spawn(f)`, and a closed context bound by
    /// one statement and spawned from by a later one.
    ///
    /// ### Example
    ///
    /// ```rust
    /// context.child("service").child("worker").spawn(f);
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust
    /// let service = context.child("service");
    /// service.child("worker").spawn(f);
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
        if !is_runtime_method(cx, expr, "Spawner", "spawn") || !handle_unused(cx, expr) {
            return;
        }

        let Some(child) = child_call(cx, receiver) else {
            return;
        };
        let ExprKind::MethodCall(_, parent, ..) = child.kind else {
            return;
        };
        if let Some(temporary) = child_call(cx, parent) {
            let span = temporary.span;
            cx.emit_span_lint(TEMPORARY_PARENT_CONTEXT, span, DiagDecorator(|diag| {
                diag.primary_message("temporary parent context");
                diag.help(
                    "the temporary parent is dropped at the end of the statement, which closes it and every context derived from it, so bind the parent context first",
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

/// Returns whether the handle `spawn` returns leaves its statement unused: discarded,
/// bound with `let`, or returned from the enclosing block, closure, or function.
fn handle_unused(cx: &LateContext<'_>, spawn: &Expr<'_>) -> bool {
    match cx.tcx.parent_hir_node(spawn.hir_id) {
        Node::Stmt(_) => true,
        Node::LetStmt(local) => local.init.is_some_and(|init| init.hir_id == spawn.hir_id),
        Node::Block(block) => block.expr.is_some_and(|tail| tail.hir_id == spawn.hir_id),
        Node::Expr(parent) => matches!(parent.kind, ExprKind::Ret(_) | ExprKind::Closure(..)),
        _ => false,
    }
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
