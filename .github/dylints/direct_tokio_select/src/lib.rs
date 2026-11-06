#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_data_structures;
extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_span;

use rustc_data_structures::fx::FxHashSet;
use rustc_errors::DiagDecorator;
use rustc_hir::Expr;
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_span::{
    ExpnId,
    hygiene::{ExpnData, ExpnKind, MacroKind},
};

/// Crate that defines the guarded macros.
const COMMONWARE_MACROS_IMPL: &str = "commonware_macros_impl";

/// Names of the guarded macros: `commonware_macros::select!` and `select_loop!`.
const GUARDED: [&str; 2] = ["select", "select_loop"];

dylint_linting::impl_late_lint! {
    /// ### What it does
    ///
    /// Detects invocations of tokio's `select!` macro, under any path or
    /// re-export and inside other macros, that the expansion of
    /// `commonware_macros::select!` or `select_loop!` did not produce. Each
    /// invocation is reported once, at its call site.
    ///
    /// ### Why is this bad?
    ///
    /// `commonware_macros::select!` wraps every branch in a guard that defers
    /// while the cooperative budget is spent, so a spent budget defers the
    /// whole select and branch order holds. A direct `tokio::select!` has no
    /// such guard. Under a spent budget a budgeted receive returns `Pending`,
    /// while a branch that does not consume the budget, such as a completed
    /// future, can complete first and overtake it, even with `biased;`.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// tokio::select! {
    ///     biased;
    ///     message = receiver.recv() => process(message),
    ///     result = &mut task => return result,
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// commonware_macros::select! {
    ///     message = receiver.recv() => process(message),
    ///     result = &mut task => return result,
    /// }
    /// ```
    pub DIRECT_TOKIO_SELECT,
    Deny,
    "`tokio::select!` that bypasses the cooperative budget guard",
    DirectTokioSelect::default()
}

#[derive(Default)]
struct DirectTokioSelect {
    /// Outermost `tokio::select!` expansions already reported.
    reported: FxHashSet<ExpnId>,
}

impl<'tcx> LateLintPass<'tcx> for DirectTokioSelect {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        // Walk the expression's macro backtrace from the innermost expansion
        // outward. Every expression that a `tokio::select!` invocation expands
        // to has that expansion in its backtrace, so the first one visited
        // reports the invocation.
        let mut ctxt = expr.span.ctxt();
        while !ctxt.is_root() {
            let mut expn = ctxt.outer_expn();
            let mut data = expn.expn_data();
            if !is_tokio_select(cx, &data) {
                ctxt = data.call_site.ctxt();
                continue;
            }

            // `tokio::select!` recurses through `$crate::select!` to normalize
            // its branches. Climb to the invocation that started the recursion:
            // its call site decides the exemption and locates the report.
            loop {
                let parent = data.call_site.ctxt().outer_expn();
                let parent_data = parent.expn_data();
                if !is_tokio_select(cx, &parent_data) {
                    break;
                }
                expn = parent;
                data = parent_data;
            }

            // An invocation that a guarded macro produced wraps its branches in
            // the guard.
            ctxt = data.call_site.ctxt();
            if is_guarded(cx, &ctxt.outer_expn_data()) || !self.reported.insert(expn) {
                continue;
            }

            // rustc drops lints whose span lies in a macro that another crate
            // defines. Report at the first call site outside such macros, so an
            // exported macro that wraps `tokio::select!` is reported where it
            // is invoked.
            let mut span = data.call_site;
            while span.in_external_macro(cx.sess().source_map()) {
                span = span.ctxt().outer_expn_data().call_site;
            }
            cx.emit_span_lint(
                DIRECT_TOKIO_SELECT,
                span,
                DiagDecorator(|diag| {
                    diag.primary_message(
                        "`tokio::select!` bypasses the cooperative budget guard, so under a spent budget a branch that is ready without the budget can overtake a budgeted receive",
                    );
                    diag.help("use `commonware_macros::select!` or `select_loop!`");
                }),
            );
        }
    }
}

/// Returns whether `data` is an expansion of a function-like macro that
/// `krate` defines under one of `names`.
///
/// Macros are matched by the crate and name of their definition, so imports,
/// re-exports, and renames all match.
fn is_macro(cx: &LateContext<'_>, data: &ExpnData, krate: &str, names: &[&str]) -> bool {
    if !matches!(data.kind, ExpnKind::Macro(MacroKind::Bang, _)) {
        return false;
    }
    let Some(def_id) = data.macro_def_id else {
        return false;
    };
    cx.tcx.crate_name(def_id.krate).as_str() == krate
        && cx
            .tcx
            .opt_item_name(def_id)
            .is_some_and(|name| names.contains(&name.as_str()))
}

/// Returns whether `data` is an expansion of tokio's `select!`.
fn is_tokio_select(cx: &LateContext<'_>, data: &ExpnData) -> bool {
    is_macro(cx, data, "tokio", &["select"])
}

/// Returns whether `data` is an expansion of `commonware_macros::select!` or
/// `select_loop!`.
fn is_guarded(cx: &LateContext<'_>, data: &ExpnData) -> bool {
    is_macro(cx, data, COMMONWARE_MACROS_IMPL, &GUARDED)
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
