#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_span;

use rustc_errors::DiagDecorator;
use rustc_hir::{
    intravisit::{walk_expr, Visitor},
    Body, Expr, ExprKind, MatchSource,
};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_span::{Span, Symbol};

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects blocking waits in actor event loops, such as awaiting an actor
    /// mailbox request/reply method or an async handler callback inside
    /// `select_loop!`. It also detects async mailbox request/reply helpers that
    /// create a oneshot channel, enqueue a message with the sender, and then
    /// await the receiver before returning.
    ///
    /// ### Why is this bad?
    ///
    /// Actor loops must keep polling their mailbox and other event sources.
    /// Awaiting another actor or an application callback from a branch body can
    /// starve the loop. Hiding the wait behind an async mailbox helper makes it
    /// too easy for actor loops to block accidentally. Spawn or pool the work
    /// and select on its completion instead.
    ///
    /// ### Example
    ///
    /// ```rust
    /// select_loop! {
    ///     context,
    ///     message = mailbox.recv() => {
    ///         handler.process(message).await;
    ///     },
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust
    /// select_loop! {
    ///     context,
    ///     message = mailbox.recv() => {
    ///         pending.push(async move {
    ///             handler.process(message).await;
    ///         });
    ///     },
    ///     _ = pending.next_completed() => {},
    /// }
    /// ```
    pub BLOCKING_IN_ACTOR_LOOP,
    Deny,
    "blocking await in actor loop"
}

impl<'tcx> LateLintPass<'tcx> for BlockingInActorLoop {
    fn check_body(&mut self, cx: &LateContext<'tcx>, body: &Body<'tcx>) {
        match actor_loop_kind(cx, body) {
            Some(kind) => BlockingAwaitVisitor { cx, kind }.visit_expr(body.value),
            None => {}
        }

        if let Some(span) = request_reply_helper_wait(cx, body) {
            cx.emit_span_lint(
                BLOCKING_IN_ACTOR_LOOP,
                span,
                DiagDecorator(|diag| {
                    diag.primary_message("async mailbox request/reply helper hides an actor wait");
                    diag.span_help(
                        span,
                        "return the oneshot receiver and let callers select or await explicitly",
                    );
                }),
            );
        }
    }
}

struct BlockingAwaitVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    kind: ActorLoopKind,
}

#[derive(Clone, Copy)]
enum ActorLoopKind {
    SelectLoop,
    MailboxWhile,
}

impl<'tcx> Visitor<'tcx> for BlockingAwaitVisitor<'_, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if let Some(call) = awaited_call(expr) {
            if call.blocks_actor_loop(self.cx, self.kind) {
                self.cx.emit_span_lint(
                    BLOCKING_IN_ACTOR_LOOP,
                    expr.span,
                    DiagDecorator(|diag| {
                        diag.primary_message("blocking await in actor loop");
                        diag.span_help(
                            call.span,
                            "queue this work and select on its completion instead of awaiting it in the actor loop",
                        );
                    }),
                );
            }
            return;
        }

        walk_expr(self, expr);
    }
}

struct AwaitedCall<'tcx> {
    receiver: Option<&'tcx Expr<'tcx>>,
    method: Symbol,
    span: Span,
}

impl AwaitedCall<'_> {
    fn blocks_actor_loop(&self, cx: &LateContext<'_>, kind: ActorLoopKind) -> bool {
        is_async_callback(self.method)
            || self
                .receiver
                .is_some_and(|receiver| is_mailbox(cx, receiver))
            || matches!(kind, ActorLoopKind::MailboxWhile)
                && is_io_wait(self.method)
                && self
                    .receiver
                    .is_none_or(|receiver| !is_mailbox_loop_recv(cx, receiver))
    }
}

fn actor_loop_kind(cx: &LateContext<'_>, body: &Body<'_>) -> Option<ActorLoopKind> {
    let snippet = cx
        .sess()
        .source_map()
        .span_to_snippet(body.value.span)
        .ok()?;

    if snippet.contains("select_loop!") {
        return Some(ActorLoopKind::SelectLoop);
    }
    if snippet.contains("mailbox.recv().await") {
        return Some(ActorLoopKind::MailboxWhile);
    }
    None
}

fn request_reply_helper_wait(cx: &LateContext<'_>, body: &Body<'_>) -> Option<Span> {
    let snippet = cx
        .sess()
        .source_map()
        .span_to_snippet(body.value.span)
        .ok()?;

    if !snippet.contains("oneshot::channel")
        || !snippet.contains(".enqueue(Message::")
        || !snippet.contains(".await")
    {
        return None;
    }

    AwaitVisitor::default().await_span(body.value)
}

#[derive(Default)]
struct AwaitVisitor {
    span: Option<Span>,
}

impl AwaitVisitor {
    fn await_span<'tcx>(mut self, expr: &'tcx Expr<'tcx>) -> Option<Span> {
        self.visit_expr(expr);
        self.span
    }
}

impl<'tcx> Visitor<'tcx> for AwaitVisitor {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if self.span.is_some() {
            return;
        }

        if matches!(expr.kind, ExprKind::Match(_, _, MatchSource::AwaitDesugar)) {
            self.span = Some(expr.span);
            return;
        }

        walk_expr(self, expr);
    }
}

fn awaited_call<'tcx>(expr: &'tcx Expr<'tcx>) -> Option<AwaitedCall<'tcx>> {
    let ExprKind::Match(awaited, _, MatchSource::AwaitDesugar) = expr.kind else {
        return None;
    };

    find_call(awaited)
}

fn find_call<'tcx>(expr: &'tcx Expr<'tcx>) -> Option<AwaitedCall<'tcx>> {
    match expr.kind {
        ExprKind::MethodCall(segment, receiver, ..) => Some(AwaitedCall {
            receiver: Some(receiver),
            method: segment.ident.name,
            span: expr.span,
        }),
        ExprKind::Call(_, args) => args.iter().find_map(find_call),
        ExprKind::Block(block, _) => block.expr.and_then(find_call),
        _ => None,
    }
}

fn is_async_callback(method: Symbol) -> bool {
    matches!(method.as_str(), "process" | "collected")
}

fn is_io_wait(method: Symbol) -> bool {
    matches!(method.as_str(), "send" | "recv")
}

fn is_mailbox(cx: &LateContext<'_>, receiver: &Expr<'_>) -> bool {
    let ty = cx.typeck_results().expr_ty(receiver).peel_refs();
    format!("{ty:?}").contains("Mailbox")
}

fn is_mailbox_loop_recv(cx: &LateContext<'_>, receiver: &Expr<'_>) -> bool {
    cx.sess()
        .source_map()
        .span_to_snippet(receiver.span)
        .is_ok_and(|snippet| snippet.ends_with("mailbox"))
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
