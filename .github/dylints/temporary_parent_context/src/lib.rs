#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;

use rustc_errors::DiagDecorator;
use rustc_hir::{
    Expr, ExprKind, MatchSource, Node,
    intravisit::{self, Visitor},
};
use rustc_lint::{LateContext, LateLintPass, LintContext};

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects `Spawner::spawn` on a `Supervisor::child` of a temporary
    /// `Supervisor::child`, in a statement that awaits nothing. Calls must resolve
    /// to the traits in `commonware_runtime`.
    ///
    /// ### Why is this bad?
    ///
    /// The temporary parent is dropped at the end of the statement and aborts
    /// the spawned task. A statement that awaits may wait for the task while
    /// the parent is alive, so the lint stays silent there, as it does for
    /// chains that do not spawn.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let worker = context.child("service").child("worker").spawn(f);
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust
    /// let service = context.child("service");
    /// let worker = service.child("worker").spawn(f);
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
        if !is_runtime_method(cx, expr, "Spawner", "spawn") || statement_awaits(cx, expr) {
            return;
        }

        let Some(child) = first_child_call(cx, receiver) else {
            return;
        };
        let ExprKind::MethodCall(_, parent, ..) = child.kind else {
            return;
        };
        if let Some(temporary) = first_child_call(cx, parent) {
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

fn first_child_call<'tcx>(
    cx: &LateContext<'tcx>,
    expr: &'tcx Expr<'tcx>,
) -> Option<&'tcx Expr<'tcx>> {
    let mut current = expr;

    while let ExprKind::MethodCall(_, receiver, ..) = current.kind {
        if current.span.from_expansion() {
            return None;
        }
        if is_runtime_method(cx, current, "Supervisor", "child") {
            return Some(current);
        }
        current = receiver;
    }

    None
}

/// Returns whether the statement around `expr` awaits anything, in which case the
/// temporaries it creates may outlive the work it spawned.
fn statement_awaits(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let mut id = expr.hir_id;
    loop {
        match cx.tcx.parent_hir_node(id) {
            Node::Expr(parent) => match parent.kind {
                ExprKind::Closure(..) => return false,
                ExprKind::Match(_, _, MatchSource::AwaitDesugar) => return true,
                _ => id = parent.hir_id,
            },
            Node::Stmt(stmt) => return contains_await(|finder| finder.visit_stmt(stmt)),
            Node::LetStmt(local) => return contains_await(|finder| finder.visit_local(local)),
            _ => return false,
        }
    }
}

/// Runs `visit` with a finder that records any `.await` outside nested bodies.
fn contains_await(visit: impl FnOnce(&mut FindsAwait)) -> bool {
    let mut finder = FindsAwait(false);
    visit(&mut finder);
    finder.0
}

/// Records whether a visited expression awaits.
struct FindsAwait(bool);

impl<'tcx> Visitor<'tcx> for FindsAwait {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if matches!(expr.kind, ExprKind::Match(_, _, MatchSource::AwaitDesugar)) {
            self.0 = true;
            return;
        }
        intravisit::walk_expr(self, expr);
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
