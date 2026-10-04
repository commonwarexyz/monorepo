#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_middle;

use rustc_errors::DiagDecorator;
use rustc_hir::{Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty::{self, Ty};

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects an owned `tracing::Span` passed as a span parent or
    /// `follows_from` source, such as `info_span!(parent: span, ...)` or
    /// `span.follows_from(cause)`.
    ///
    /// ### Why is this bad?
    ///
    /// Tracing converts an owned span into its ID and drops the handle before the
    /// ID is used. If no other handle is alive at that moment, for example because
    /// another task released its handle concurrently, the span has already
    /// closed. `tracing-subscriber`'s registry then panics while registering a
    /// child span, and an event or `follows_from` link refers to a closed span.
    /// Borrowing keeps the handle alive during the call, regardless of who else
    /// owns the span.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// let process = info_span!(parent: span, "component.process");
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// let process = info_span!(parent: &span, "component.process");
    /// ```
    pub OWNED_SPAN_PARENT,
    Deny,
    "owned tracing span passed as a span parent or follows_from source"
}

fn is_tracing_type(cx: &LateContext<'_>, ty: Ty<'_>, crate_name: &str, name: &str) -> bool {
    let ty::Adt(adt, _) = ty.kind() else {
        return false;
    };
    cx.tcx.crate_name(adt.did().krate).as_str() == crate_name
        && cx.tcx.item_name(adt.did()).as_str() == name
}

impl<'tcx> LateLintPass<'tcx> for OwnedSpanParent {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let (def_id, args) = match expr.kind {
            ExprKind::Call(callee, args) => {
                let ty::FnDef(def_id, _) = *cx.typeck_results().expr_ty(callee).kind() else {
                    return;
                };
                (def_id, args)
            }
            ExprKind::MethodCall(_, _, args, _) => {
                let Some(def_id) = cx.typeck_results().type_dependent_def_id(expr.hir_id) else {
                    return;
                };
                (def_id, args)
            }
            _ => return,
        };

        // Span and event macros with `parent:` and
        // `#[instrument(parent = ..., follows_from = ...)]` expand to these
        // functions, which take the parent or `follows_from` source as
        // `impl Into<Option<Id>>`.
        let Some(impl_id) = cx.tcx.impl_of_assoc(def_id) else {
            return;
        };
        let owner = cx.tcx.type_of(impl_id).skip_binder();
        let name = cx.tcx.item_name(def_id);
        let converts = if is_tracing_type(cx, owner, "tracing", "Span") {
            matches!(name.as_str(), "child_of" | "child_of_with" | "follows_from")
        } else if is_tracing_type(cx, owner, "tracing_core", "Event") {
            matches!(name.as_str(), "child_of" | "new_child_of")
        } else {
            false
        };
        if !converts {
            return;
        }

        // Only the parent or `follows_from` source parameter of these functions
        // accepts a `Span`, so every owned `Span` argument is one tracing
        // converts. Checking all arguments also covers the
        // `Span::follows_from(&span, cause)` call form. A span produced inside a
        // macro, such as the loop variable that
        // `#[instrument(follows_from = ...)]` iterates with, is reported at the
        // macro call.
        for arg in args {
            if !is_tracing_type(cx, cx.typeck_results().expr_ty(arg), "tracing", "Span") {
                continue;
            }
            cx.emit_span_lint(
                OWNED_SPAN_PARENT,
                arg.span.source_callsite(),
                DiagDecorator(|diag| {
                    diag.primary_message(
                        "owned `Span` passed as a tracing span parent or `follows_from` source",
                    );
                    diag.note(
                        "tracing drops an owned span while converting it to an ID, which can leave the ID referring to a closed span",
                    );
                    diag.help("pass a reference to the span");
                }),
            );
        }
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test_examples(env!("CARGO_PKG_NAME"));
}
