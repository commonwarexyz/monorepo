#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use rustc_errors::DiagDecorator;
use rustc_hir::{Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty::{self, Ty};
use rustc_span::{
    hygiene::{ExpnKind, MacroKind},
    Span,
};

const SPAN_MACROS: &[&str] = &[
    "span",
    "trace_span",
    "debug_span",
    "info_span",
    "warn_span",
    "error_span",
];

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects integer-valued `tracing` span fields recorded via `Display`
    /// (`%x`) or `Debug` (`?x`).
    ///
    /// ### Why is this bad?
    ///
    /// `%`/`?` record the field as a STRING attribute. `tracing-opentelemetry`'s
    /// span exporter implements `record_i64`/`record_f64` but not `record_u64`,
    /// so even a bare `u64` is stringified. String span attributes can only be
    /// matched with `=`/regex in TraceQL and sort lexicographically
    /// (`"100" < "70"`). Ordered integer fields should be recorded numerically
    /// to be range-queryable and to sort correctly.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// info_span!("simplex.voter.view", view = %view, epoch = %epoch);
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// info_span!("simplex.voter.view", view = view.traced(), epoch = epoch.traced());
    /// ```
    pub TRACING_INT_FIELDS,
    Deny,
    "integer-valued field recorded as a tracing span field via Display/Debug instead of as an integer"
}

/// Returns true if `path` equals `tail` or ends with `::{tail}` (a path-segment
/// boundary), so `field::display` matches `tracing_core::field::display`.
fn path_has_tail(path: &str, tail: &str) -> bool {
    path == tail || path.ends_with(&format!("::{tail}"))
}

/// Returns the final `::`-separated segment of a macro path, so path-qualified
/// invocations (`tracing::info_span!`, `$crate::span!`) match the bare macro name.
fn last_segment(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

/// Returns true when this expression was generated while expanding a tracing
/// span macro or `#[instrument]`. Events are intentionally allowed to keep `%`
/// and `?` formatting because they are log records, not range-queryable span
/// attributes.
fn in_span_macro(span: Span) -> bool {
    span.macro_backtrace().any(|expn| match expn.kind {
        ExpnKind::Macro(MacroKind::Bang, name) => {
            SPAN_MACROS.contains(&last_segment(name.as_str()))
        }
        ExpnKind::Macro(MacroKind::Attr, name) => last_segment(name.as_str()) == "instrument",
        _ => false,
    })
}

/// Returns true if `ty` is an integer primitive or a single-field newtype
/// wrapping an integer (e.g. `View(u64)`, `Epoch(u64)`, `Height(u64)`). These
/// should be recorded as `i64`, not via `Display`/`Debug`.
fn is_integer_like(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    if ty.is_integral() {
        return true;
    }
    let ty::Adt(adt, _args) = ty.kind() else {
        return false;
    };
    if !adt.is_struct() {
        return false;
    }
    let [field] = &adt.non_enum_variant().fields.raw[..] else {
        return false;
    };
    cx.tcx.type_of(field.did).skip_binder().is_integral()
}

impl<'tcx> LateLintPass<'tcx> for TracingIntFields {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        // `%x` / `?x` in a tracing macro expand to `tracing::field::display(&x)`
        // and `tracing::field::debug(&x)` respectively.
        let ExprKind::Call(callee, [arg]) = expr.kind else {
            return;
        };
        let ExprKind::Path(qpath) = &callee.kind else {
            return;
        };
        let Some(callee_id) = cx.qpath_res(qpath, callee.hir_id).opt_def_id() else {
            return;
        };
        let callee_path = cx.tcx.def_path_str(callee_id);
        let recorder = if path_has_tail(&callee_path, "field::display") {
            "Display (%)"
        } else if path_has_tail(&callee_path, "field::debug") {
            "Debug (?)"
        } else {
            return;
        };
        if !in_span_macro(expr.span) {
            return;
        }

        let arg_ty = cx.typeck_results().expr_ty(arg).peel_refs();
        if !is_integer_like(cx, arg_ty) {
            return;
        }
        let ty_name = arg_ty.to_string();
        let value_span = match arg.kind {
            ExprKind::AddrOf(_, _, inner) => inner.span,
            _ => arg.span,
        };

        cx.emit_span_lint(
            TRACING_INT_FIELDS,
            value_span.source_callsite(),
            DiagDecorator(move |diag| {
                diag.primary_message(format!(
                    "integer-valued `{ty_name}` recorded as a tracing span field via {recorder}; record it as an integer"
                ));
                diag.help(
                    "record it as an integer, e.g. `field = value.traced()`; `tracing-opentelemetry` records Display/Debug span fields (and even a bare `u64`) as strings, which TraceQL cannot range-query or sort numerically",
                );
            }),
        );
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
