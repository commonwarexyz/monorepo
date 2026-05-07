#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_hir;
extern crate rustc_span;

use rustc_hir::{def::Res, AmbigArg, Expr, ExprKind, HirId, QPath, Ty, TyKind};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_span::Span;

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects raw `mpsc` sender/receiver endpoints and channel construction in
    /// actor modules.
    ///
    /// ### Why is this bad?
    ///
    /// Actor-to-actor messages should be sent through `ActorMailbox` so enqueue
    /// behavior is explicit and callers cannot accidentally await destination
    /// mailbox capacity.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let (sender, receiver) = mpsc::channel(8);
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust
    /// let (sender, receiver) = actor::channel(8);
    /// ```
    pub ACTOR_MAILBOX,
    Deny,
    "raw mpsc actor mailbox"
}

impl<'tcx> LateLintPass<'tcx> for ActorMailbox {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if expr.span.from_expansion() || !is_actor_context(cx, expr.hir_id, expr.span) {
            return;
        }

        let ExprKind::Call(callee, _) = expr.kind else {
            return;
        };
        let ExprKind::Path(ref qpath) = callee.kind else {
            return;
        };

        if is_mpsc_channel_fn(cx, qpath, callee.hir_id) {
            cx.span_lint(ACTOR_MAILBOX, callee.span, |diag| {
                diag.primary_message("raw mpsc actor mailbox");
                diag.span_help(
                    callee.span,
                    "create an ActorMailbox with actor::channel instead",
                );
            });
        }
    }

    fn check_ty(&mut self, cx: &LateContext<'tcx>, ty: &'tcx Ty<'tcx, AmbigArg>) {
        if ty.span.from_expansion() || !is_actor_context(cx, ty.hir_id, ty.span) {
            return;
        }

        let TyKind::Path(ref qpath) = ty.kind else {
            return;
        };

        if is_mpsc_endpoint(cx, qpath, ty.hir_id) {
            cx.span_lint(ACTOR_MAILBOX, ty.span, |diag| {
                diag.primary_message("raw mpsc actor mailbox");
                diag.span_help(ty.span, "store ActorMailbox or ActorInbox instead");
            });
        }
    }
}

fn is_actor_context(cx: &LateContext<'_>, hir_id: HirId, span: Span) -> bool {
    if is_mailbox_implementation(cx, span) {
        return false;
    }

    let module = cx.tcx.parent_module(hir_id).to_def_id();
    let path = cx.tcx.def_path_str(module);

    if path
        .split("::")
        .any(|segment| matches!(segment, "test" | "tests" | "mocks"))
    {
        return false;
    }

    path.split("::")
        .any(|segment| matches!(segment, "actor" | "actors" | "ingress" | "relay"))
}

fn is_mailbox_implementation(cx: &LateContext<'_>, span: Span) -> bool {
    let filename = cx.sess().source_map().span_to_filename(span);
    let filename = filename.prefer_local().to_string_lossy();
    filename.ends_with("/channel/actor.rs") || filename.ends_with("\\channel\\actor.rs")
}

fn is_mpsc_channel_fn(cx: &LateContext<'_>, qpath: &QPath<'_>, hir_id: HirId) -> bool {
    resolved_path(cx, qpath, hir_id).is_some_and(|path| {
        is_mpsc_path(&path)
            && (path.ends_with("::channel") || path.ends_with("::unbounded_channel"))
    })
}

fn is_mpsc_endpoint(cx: &LateContext<'_>, qpath: &QPath<'_>, hir_id: HirId) -> bool {
    resolved_path(cx, qpath, hir_id).is_some_and(|path| {
        is_mpsc_path(&path)
            && (path.ends_with("::Sender")
                || path.ends_with("::Receiver")
                || path.ends_with("::UnboundedSender")
                || path.ends_with("::UnboundedReceiver"))
    })
}

fn is_mpsc_path(path: &str) -> bool {
    path.contains("tokio::sync::mpsc") || path.contains("commonware_utils::channel::mpsc")
}

fn resolved_path(cx: &LateContext<'_>, qpath: &QPath<'_>, hir_id: HirId) -> Option<String> {
    match cx.qpath_res(qpath, hir_id) {
        Res::Def(_, def_id) => Some(cx.tcx.def_path_str(def_id)),
        _ => None,
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
