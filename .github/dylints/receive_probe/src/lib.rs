#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use rustc_errors::DiagDecorator;
use rustc_hir::{Expr, ExprKind, def_id::DefId};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty::{self, Ty};
use rustc_span::{Symbol, sym};

/// Definition path of `futures::FutureExt::now_or_never`.
const NOW_OR_NEVER: &[&str] = &[
    "futures_util",
    "future",
    "future",
    "FutureExt",
    "now_or_never",
];

/// Definition path of the `commonware_p2p::Receiver::recv` trait method.
const P2P_RECV: &[&str] = &["commonware_p2p", "Receiver", "recv"];

/// Definition paths of oneshot receivers, which are themselves futures that take
/// part in a cooperative budget.
const ONESHOT_RECEIVERS: &[&[&str]] = &[
    &["commonware_utils", "channel", "oneshot", "Receiver"],
    &["tokio", "sync", "oneshot", "Receiver"],
];

/// Definition paths of watch receivers whose `changed` and `wait_for` futures
/// take part in a cooperative budget.
const WATCH_RECEIVERS: &[&[&str]] = &[
    &["commonware_utils", "channel", "watch", "Receiver"],
    &["tokio", "sync", "watch", "Receiver"],
];

/// Definition paths of receivers whose `recv` and `next` futures take part in a
/// cooperative budget.
const RECEIVERS: &[&[&str]] = &[
    &["commonware_utils", "channel", "mpsc", "Receiver"],
    &["commonware_utils", "channel", "mpsc", "UnboundedReceiver"],
    &["commonware_utils", "channel", "ring", "Receiver"],
    &["commonware_actor", "mailbox", "Receiver"],
    &["commonware_actor", "mailbox", "UnreliableReceiver"],
    &["commonware_p2p", "simulated", "network", "Receiver"],
    &["tokio", "sync", "mpsc", "bounded", "Receiver"],
    &["tokio", "sync", "mpsc", "unbounded", "UnboundedReceiver"],
];

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects `now_or_never` applied directly to a budgeted receive future:
    ///
    /// - a `recv` or `next` call on a `commonware_utils` mpsc or ring receiver, a
    ///   `commonware_actor` mailbox receiver, a Tokio mpsc receiver, or a simulated
    ///   `commonware_p2p` receiver, and any call of the `commonware_p2p::Receiver::recv`
    ///   trait method,
    /// - a `commonware_utils` or Tokio oneshot receiver, which is itself a future,
    ///   reached through references, `Box` or `Pin`,
    /// - a `changed` or `wait_for` call on a `commonware_utils` or Tokio watch
    ///   receiver.
    ///
    /// Both the method form and the fully qualified `FutureExt::now_or_never(...)`
    /// form are detected.
    ///
    /// ### Why is this bad?
    ///
    /// These receive futures take part in the task's cooperative budget (the
    /// commonware budget on the io_uring and deterministic runtimes, Tokio's own
    /// budget for Tokio's channels on the Tokio runtime). Once that budget is
    /// spent, the future wakes its waker and returns `Pending` even when a value
    /// is ready. `now_or_never` polls once with a waker that discards the wake, so the
    /// probe reports the ready value as absent and nothing polls it again.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// if let Some(Some(message)) = receiver.recv().now_or_never() {
    ///     handle(message);
    /// }
    /// if let Some(Ok(response)) = (&mut oneshot).now_or_never() {
    ///     handle(response);
    /// }
    /// if let Some(Ok(())) = watch.changed().now_or_never() {
    ///     handle(*watch.borrow_and_update());
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// if let Ok(message) = receiver.try_recv() {
    ///     handle(message);
    /// }
    /// if let Ok(response) = oneshot.try_recv() {
    ///     handle(response);
    /// }
    /// if watch.has_changed() == Ok(true) {
    ///     handle(*watch.borrow_and_update());
    /// }
    /// ```
    pub RECEIVE_PROBE,
    Deny,
    "`now_or_never` probe of a budgeted receive future"
}

/// A rejected probe, by the kind of receive future it polls.
#[derive(Clone, Copy)]
enum Probe {
    /// A `recv` or `next` call.
    Receive,
    /// A oneshot receiver.
    Oneshot,
    /// A watch receiver's `changed` call.
    Change,
    /// A watch receiver's `wait_for` call.
    WaitFor,
}

impl Probe {
    /// Classifies the future that `now_or_never` polls.
    fn of<'tcx>(cx: &LateContext<'tcx>, future: &'tcx Expr<'tcx>) -> Option<Self> {
        if is_receive(cx, future) {
            Some(Self::Receive)
        } else if is_oneshot(cx, future) {
            Some(Self::Oneshot)
        } else {
            watch(cx, future)
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Receive => {
                "`now_or_never` probe of a receive future can miss a queued value once the cooperative budget is spent"
            }
            Self::Oneshot => {
                "`now_or_never` probe of a oneshot receiver can miss a sent value once the cooperative budget is spent"
            }
            Self::Change | Self::WaitFor => {
                "`now_or_never` probe of a watch change can miss a new value once the cooperative budget is spent"
            }
        }
    }

    fn help(self) -> &'static str {
        match self {
            Self::Receive | Self::Oneshot => {
                "use the receiver's `try_recv`, which a spent cooperative budget never refuses"
            }
            Self::Change => {
                "use the receiver's `has_changed`, which a spent cooperative budget never refuses"
            }
            Self::WaitFor => {
                "check the value from the receiver's `borrow`, which a spent cooperative budget never refuses"
            }
        }
    }
}

impl<'tcx> LateLintPass<'tcx> for ReceiveProbe {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let Some((def_id, args)) = call(cx, expr) else {
            return;
        };
        let [future] = args[..] else {
            return;
        };
        if !is_path(cx, def_id, NOW_OR_NEVER) {
            return;
        }
        let Some(probe) = Probe::of(cx, future) else {
            return;
        };
        cx.emit_span_lint(
            RECEIVE_PROBE,
            expr.span,
            DiagDecorator(|diag| {
                diag.primary_message(probe.message());
                diag.help(probe.help());
            }),
        );
    }
}

/// Returns the callee and the arguments, receiver first, of a method call or of
/// a call of a function item.
fn call<'tcx>(
    cx: &LateContext<'tcx>,
    expr: &'tcx Expr<'tcx>,
) -> Option<(DefId, Vec<&'tcx Expr<'tcx>>)> {
    let typeck = cx.typeck_results();
    match expr.kind {
        ExprKind::MethodCall(_, receiver, args, _) => {
            let def_id = typeck.type_dependent_def_id(expr.hir_id)?;
            Some((def_id, std::iter::once(receiver).chain(args).collect()))
        }
        ExprKind::Call(callee, args) => {
            let ty::FnDef(def_id, _) = *typeck.expr_ty(callee).kind() else {
                return None;
            };
            Some((def_id, args.iter().collect()))
        }
        _ => None,
    }
}

/// Returns whether `expr` creates a budgeted receive future.
fn is_receive<'tcx>(cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) -> bool {
    let Some((def_id, args)) = call(cx, expr) else {
        return false;
    };
    let name = cx.tcx.item_name(def_id);
    if name != Symbol::intern("recv") && name != sym::next {
        return false;
    }

    // A call of the `commonware_p2p::Receiver` trait method on any type.
    let trait_item = if cx.tcx.trait_of_assoc(def_id).is_some() {
        Some(def_id)
    } else {
        cx.tcx.trait_item_of(def_id)
    };
    if trait_item.is_some_and(|id| is_path(cx, id, P2P_RECV)) {
        return true;
    }

    // A `recv` or `next` call on one of the budgeted receivers, after auto-deref.
    let Some(receiver) = args.first() else {
        return false;
    };
    is_adt(
        cx,
        cx.typeck_results().expr_ty_adjusted(receiver).peel_refs(),
        RECEIVERS,
    )
}

/// Returns whether `expr` is a oneshot receiver, through references, `Box` and
/// `Pin`.
fn is_oneshot<'tcx>(cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) -> bool {
    let mut ty = cx.typeck_results().expr_ty_adjusted(expr);
    loop {
        ty = ty.peel_refs();
        match ty.kind() {
            ty::Adt(adt, args)
                if adt.is_box() || cx.tcx.lang_items().pin_type() == Some(adt.did()) =>
            {
                ty = args.type_at(0);
            }
            _ => return is_adt(cx, ty, ONESHOT_RECEIVERS),
        }
    }
}

/// Classifies `expr` if it is a `changed` or `wait_for` call on a watch receiver.
fn watch<'tcx>(cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) -> Option<Probe> {
    let (def_id, args) = call(cx, expr)?;
    let name = cx.tcx.item_name(def_id);
    let probe = if name == Symbol::intern("changed") {
        Probe::Change
    } else if name == Symbol::intern("wait_for") {
        Probe::WaitFor
    } else {
        return None;
    };
    let receiver = args.first()?;
    is_adt(
        cx,
        cx.typeck_results().expr_ty_adjusted(receiver).peel_refs(),
        WATCH_RECEIVERS,
    )
    .then_some(probe)
}

/// Returns whether `ty` is an ADT defined at one of `paths`.
fn is_adt(cx: &LateContext<'_>, ty: Ty<'_>, paths: &[&[&str]]) -> bool {
    let ty::Adt(adt, _) = ty.kind() else {
        return false;
    };
    paths.iter().any(|path| is_path(cx, adt.did(), path))
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
