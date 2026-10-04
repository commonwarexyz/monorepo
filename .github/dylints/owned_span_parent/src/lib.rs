#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_middle;

use rustc_errors::{Applicability, DiagDecorator};
use rustc_hir::{Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty::{self, Ty};

/// Tracing functions that take a span parent or `follows_from` source as
/// `impl Into<Option<Id>>`. Span and event macros with `parent:` and
/// `#[instrument(parent = ..., follows_from = ...)]` expand to these calls.
const PARENT_FUNCTIONS: &[&str] = &[
    "Span::child_of",
    "Span::child_of_with",
    "Span::follows_from",
    "Event::child_of",
    "Event::new_child_of",
];

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
    /// subscriber uses that ID. If no other handle is alive at that moment, for
    /// example because another task released its handle concurrently, the span
    /// has already closed and `tracing-subscriber`'s registry panics while
    /// registering the child. A borrowed span stays open until the subscriber
    /// holds its own reference, regardless of who else owns the span.
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

/// Returns true if `path` equals `tail` or ends with `::{tail}` (a path-segment
/// boundary), so `Span::child_of` matches `tracing::Span::child_of`.
fn path_has_tail(path: &str, tail: &str) -> bool {
    path == tail || path.ends_with(&format!("::{tail}"))
}

/// Removes generic arguments from a printed path, so the method of a generic
/// type such as `Event::<'a>::child_of` matches `Event::child_of`.
fn without_generics(path: &str) -> String {
    let mut stripped = String::with_capacity(path.len());
    let mut depth = 0usize;
    for c in path.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => stripped.push(c),
            _ => {}
        }
    }
    stripped.replace("::::", "::")
}

fn is_tracing_span(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    let ty::Adt(adt, _) = ty.kind() else {
        return false;
    };
    let path = cx.tcx.def_path_str(adt.did());
    path_has_tail(&path, "tracing::Span") || path_has_tail(&path, "tracing::span::Span")
}

impl<'tcx> LateLintPass<'tcx> for OwnedSpanParent {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let (def_id, args) = match expr.kind {
            ExprKind::Call(callee, args) => {
                let ExprKind::Path(qpath) = &callee.kind else {
                    return;
                };
                let Some(def_id) = cx.qpath_res(qpath, callee.hir_id).opt_def_id() else {
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
        let path = without_generics(&cx.tcx.def_path_str(def_id));
        if !PARENT_FUNCTIONS
            .iter()
            .any(|function| path_has_tail(&path, function))
        {
            return;
        }

        // Only the parent or `follows_from` source parameter of these functions
        // accepts a `Span`, so every owned `Span` argument is one tracing
        // converts. Checking all arguments also covers the
        // `Span::follows_from(&span, cause)` call form.
        for arg in args {
            if is_tracing_span(cx, cx.typeck_results().expr_ty(arg)) {
                report(cx, arg);
            }
        }
    }
}

fn report(cx: &LateContext<'_>, arg: &Expr<'_>) {
    // A span written by the caller can be borrowed in place. A span produced
    // inside a macro, such as the loop variable that
    // `#[instrument(follows_from = ...)]` iterates with, has no caller-written
    // source to rewrite, so it is reported at the macro call without a
    // suggestion.
    let snippet = if arg.span.from_expansion() {
        None
    } else {
        cx.sess().source_map().span_to_snippet(arg.span).ok()
    };
    let span = arg.span.source_callsite();
    cx.emit_span_lint(
        OWNED_SPAN_PARENT,
        span,
        DiagDecorator(move |diag| {
            diag.primary_message(
                "owned `Span` passed as a tracing span parent or `follows_from` source",
            );
            diag.note(
                "tracing drops this handle before using the span's ID; if no other handle is alive, the span has closed and the subscriber panics",
            );
            match snippet {
                Some(snippet) => {
                    diag.span_suggestion(
                        span,
                        "borrow the span",
                        format!("&{snippet}"),
                        Applicability::MachineApplicable,
                    );
                }
                None => {
                    diag.help("pass a reference to the span");
                }
            }
        }),
    );
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
