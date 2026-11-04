#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use rustc_errors::DiagDecorator;
use rustc_hir::{CoroutineDesugaring, CoroutineKind, Expr, ExprKind, def::DefKind, def_id::DefId};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty;
use rustc_span::Symbol;

/// Definition path of `futures::executor::block_on`.
const BLOCK_ON: &[&str] = &["futures_executor", "local_pool", "block_on"];

/// Definition path of `futures::Stream`.
const STREAM: &[&str] = &["futures_core", "stream", "Stream"];

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects calls of `futures::executor::block_on` whose immediately enclosing
    /// body is polled as a task: an `async` function, block, or closure, or a
    /// `poll` or `poll_*` method of a `Future` or `Stream` implementation.
    /// Calls inside a non-async closure, which may run on another thread, and in
    /// synchronous functions are not reported.
    ///
    /// ### Why is this bad?
    ///
    /// `block_on` runs a nested executor that parks the calling thread until its
    /// future completes. Inside a task poll it holds the worker, so nothing else
    /// scheduled there makes progress. Once the outer poll has spent its
    /// cooperative budget, a budgeted receive keeps returning `Pending` while
    /// waking itself, so the nested executor spins, and a receive whose sender
    /// runs on the held worker deadlocks.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// async fn run(mut receiver: Receiver<Message>) {
    ///     let message = futures::executor::block_on(receiver.recv());
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// async fn run(mut receiver: Receiver<Message>) {
    ///     let message = receiver.recv().await;
    /// }
    /// ```
    pub BLOCK_ON_IN_ASYNC,
    Deny,
    "`block_on` inside an async body or a poll method"
}

impl<'tcx> LateLintPass<'tcx> for BlockOnInAsync {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let ExprKind::Call(callee, _) = expr.kind else {
            return;
        };
        let ty::FnDef(def_id, _) = *cx.typeck_results().expr_ty(callee).kind() else {
            return;
        };
        if !is_path(cx, def_id, BLOCK_ON) {
            return;
        }
        let Some(body) = cx.enclosing_body else {
            return;
        };
        let owner = cx.tcx.hir_body_owner_def_id(body).to_def_id();
        let help = if is_async(cx, owner) {
            "await the future instead"
        } else if is_poll(cx, owner) {
            "poll the future with this poll's context instead"
        } else {
            return;
        };
        cx.emit_span_lint(
            BLOCK_ON_IN_ASYNC,
            expr.span,
            DiagDecorator(|diag| {
                diag.primary_message(
                    "blocking inside an async poll holds the worker, and under a cooperative budget a blocked receive can spin or deadlock",
                );
                diag.help(help);
            }),
        );
    }
}

/// Returns whether `owner`s body is an `async` function, block, or closure body.
fn is_async(cx: &LateContext<'_>, owner: DefId) -> bool {
    cx.tcx.def_kind(owner) == DefKind::Closure
        && matches!(
            cx.tcx.coroutine_kind(owner),
            Some(CoroutineKind::Desugared(
                CoroutineDesugaring::Async | CoroutineDesugaring::AsyncGen,
                _
            ))
        )
}

/// Returns whether `owner` is a `poll` or `poll_*` method of a `Future` or
/// `Stream` implementation.
fn is_poll(cx: &LateContext<'_>, owner: DefId) -> bool {
    if cx.tcx.def_kind(owner) != DefKind::AssocFn {
        return false;
    }
    let name = cx.tcx.item_name(owner);
    if name.as_str() != "poll" && !name.as_str().starts_with("poll_") {
        return false;
    }
    let Some(implementation) = cx.tcx.trait_impl_of_assoc(owner) else {
        return false;
    };
    let trait_id = cx.tcx.impl_trait_id(implementation);
    cx.tcx.lang_items().future_trait() == Some(trait_id) || is_path(cx, trait_id, STREAM)
}

/// Returns whether `def_id`'s definition path is `path`.
fn is_path(cx: &LateContext<'_>, def_id: DefId, path: &[&str]) -> bool {
    cx.get_def_path(def_id)
        .iter()
        .map(Symbol::as_str)
        .eq(path.iter().copied())
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
