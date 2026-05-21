#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_ast;
extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use rustc_ast::ast::LitKind;
use rustc_errors::DiagDecorator;
use rustc_hir::{
    intravisit::{self, Visitor},
    Arm, BodyId, Expr, ExprKind, FnDecl, FnRetTy, ImplItem, ImplItemKind, ItemKind, Node, Pat,
    PatExprKind, PatKind, QPath, Ty, TyKind,
};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty;
use rustc_span::{
    def_id::{DefId, LocalDefId},
    Span, Symbol,
};
use std::collections::{HashMap, HashSet};

dylint_linting::impl_late_lint! {
    /// ### What it does
    ///
    /// Detects functions that return plain `Feedback` from a mailbox whose
    /// [`Policy::handle`] implementation can return `false`.
    ///
    /// ### Why is this bad?
    ///
    /// A mailbox policy that returns `false` rejects live work under backpressure.
    /// Returning `Lossy<Feedback>` makes that lossy contract explicit at the API
    /// boundary.
    ///
    /// ### Example
    ///
    /// ```rust
    /// fn submit(&self, message: Message) -> Feedback {
    ///     self.sender.enqueue(message)
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust
    /// fn submit(&self, message: Message) -> Lossy<Feedback> {
    ///     self.sender.enqueue_lossy(message)
    /// }
    /// ```
    pub LOSSY_FEEDBACK,
    Deny,
    "lossy mailbox returns plain Feedback",
    LossyFeedback::default()
}

#[derive(Default)]
pub struct LossyFeedback {
    lossy_messages: HashMap<DefId, LossyPolicy>,
}

#[derive(Default)]
struct LossyPolicy {
    all: bool,
    variants: HashSet<Symbol>,
}

impl LossyPolicy {
    fn merge(&mut self, other: LossyPolicy) {
        self.all |= other.all;
        self.variants.extend(other.variants);
    }

    fn is_empty(&self) -> bool {
        !self.all && self.variants.is_empty()
    }
}

impl<'tcx> LateLintPass<'tcx> for LossyFeedback {
    fn check_impl_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx ImplItem<'tcx>) {
        let ImplItemKind::Fn(_, body_id) = item.kind else {
            return;
        };
        if item.ident.name != Symbol::intern("handle") {
            return;
        }

        let Some(message) = policy_self_ty(cx, item) else {
            return;
        };
        let policy = lossy_policy(cx, body_id);
        if !policy.is_empty() {
            self.lossy_messages.insert(message, policy);
        }
    }

    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        _kind: rustc_hir::intravisit::FnKind<'tcx>,
        decl: &'tcx FnDecl<'tcx>,
        body: &'tcx rustc_hir::Body<'tcx>,
        _span: Span,
        _id: LocalDefId,
    ) {
        if !returns_plain_feedback(decl) {
            return;
        }

        let mut visitor = LossyEnqueueVisitor {
            cx,
            lossy_messages: &self.lossy_messages,
            span: None,
        };
        visitor.visit_expr(body.value);

        if let Some(span) = visitor.span {
            cx.emit_span_lint(
                LOSSY_FEEDBACK,
                span,
                DiagDecorator(|diag| {
                    diag.primary_message("lossy mailbox returns plain Feedback");
                    diag.span_help(span, "use enqueue_lossy and return Lossy<Feedback>");
                }),
            );
        }
    }
}

fn policy_self_ty(cx: &LateContext<'_>, item: &ImplItem<'_>) -> Option<DefId> {
    let Node::Item(parent) = cx.tcx.parent_hir_node(item.hir_id()) else {
        return None;
    };
    let ItemKind::Impl(impl_) = parent.kind else {
        return None;
    };
    let trait_ref = impl_.of_trait.as_ref()?;
    if trait_ref.trait_ref.path.segments.last()?.ident.name != Symbol::intern("Policy") {
        return None;
    }
    ty_def_id(impl_.self_ty)
}

fn ty_def_id(ty: &Ty<'_>) -> Option<DefId> {
    let TyKind::Path(QPath::Resolved(_, path)) = ty.kind else {
        return None;
    };
    path.res.opt_def_id()
}

fn lossy_policy(cx: &LateContext<'_>, body_id: BodyId) -> LossyPolicy {
    let body = cx.tcx.hir_body(body_id);
    let mut policy = LossyPolicy::default();

    let mut visitor = ReturnVisitor {
        policy: &mut policy,
    };
    visitor.visit_expr(body.value);
    collect_tail_lossy(body.value, &mut policy);

    policy
}

struct ReturnVisitor<'a> {
    policy: &'a mut LossyPolicy,
}

impl<'tcx> Visitor<'tcx> for ReturnVisitor<'_> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        match expr.kind {
            ExprKind::Closure(_) => {}
            ExprKind::Ret(Some(value)) => {
                if bool_value(value) == Some(false) {
                    self.policy.all = true;
                }
                intravisit::walk_expr(self, expr);
            }
            _ => intravisit::walk_expr(self, expr),
        }
    }
}

fn collect_tail_lossy(expr: &Expr<'_>, policy: &mut LossyPolicy) {
    match expr.kind {
        ExprKind::Block(block, _) => {
            if let Some(expr) = block.expr {
                collect_tail_lossy(expr, policy);
            }
        }
        ExprKind::If(_, then, Some(otherwise)) => {
            collect_tail_lossy(then, policy);
            collect_tail_lossy(otherwise, policy);
        }
        ExprKind::If(_, then, None) => collect_tail_lossy(then, policy),
        ExprKind::Match(_, arms, _) => collect_match_lossy(arms, policy),
        ExprKind::Closure(_) => {}
        _ => {
            if bool_value(expr) == Some(false) {
                policy.all = true;
            }
        }
    }
}

fn collect_match_lossy(arms: &[Arm<'_>], policy: &mut LossyPolicy) {
    for arm in arms {
        let mut arm_policy = LossyPolicy::default();
        collect_tail_lossy(arm.body, &mut arm_policy);
        if arm_policy.is_empty() {
            continue;
        }
        if arm_policy.all {
            collect_lossy_pattern(arm.pat, policy);
        } else {
            policy.merge(arm_policy);
        }
    }
}

fn collect_lossy_pattern(pat: &Pat<'_>, policy: &mut LossyPolicy) {
    match pat.kind {
        PatKind::Struct(qpath, ..) | PatKind::TupleStruct(qpath, ..) => {
            if let Some(variant) = qpath_name(qpath) {
                policy.variants.insert(variant);
            } else {
                policy.all = true;
            }
        }
        PatKind::Expr(expr) => {
            if let PatExprKind::Path(qpath) = expr.kind {
                if let Some(variant) = qpath_name(qpath) {
                    policy.variants.insert(variant);
                } else {
                    policy.all = true;
                }
            } else {
                policy.all = true;
            }
        }
        PatKind::Or(pats) => {
            for pat in pats {
                collect_lossy_pattern(pat, policy);
            }
        }
        PatKind::Binding(_, _, _, Some(pat)) | PatKind::Ref(pat, _, _) => {
            collect_lossy_pattern(pat, policy);
        }
        _ => policy.all = true,
    }
}

fn bool_value(expr: &Expr<'_>) -> Option<bool> {
    if let ExprKind::Lit(lit) = expr.kind {
        if let LitKind::Bool(value) = lit.node {
            return Some(value);
        }
    }
    None
}

fn returns_plain_feedback(decl: &FnDecl<'_>) -> bool {
    let FnRetTy::Return(ty) = decl.output else {
        return false;
    };
    path_ty_name(ty) == Some(Symbol::intern("Feedback"))
}

fn path_ty_name(ty: &Ty<'_>) -> Option<Symbol> {
    let TyKind::Path(QPath::Resolved(_, path)) = ty.kind else {
        return None;
    };
    Some(path.segments.last()?.ident.name)
}

fn qpath_name(qpath: QPath<'_>) -> Option<Symbol> {
    match qpath {
        QPath::Resolved(_, path) => Some(path.segments.last()?.ident.name),
        QPath::TypeRelative(_, segment) => Some(segment.ident.name),
    }
}

struct LossyEnqueueVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    lossy_messages: &'a HashMap<DefId, LossyPolicy>,
    span: Option<Span>,
}

impl<'tcx> Visitor<'tcx> for LossyEnqueueVisitor<'_, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if self.span.is_some() || expr.span.from_expansion() {
            return;
        }

        match expr.kind {
            ExprKind::Closure(_) => {}
            ExprKind::MethodCall(segment, receiver, args, _)
                if segment.ident.name == Symbol::intern("enqueue")
                    && self.enqueue_is_lossy(receiver, args.first()) =>
            {
                self.span = Some(expr.span);
            }
            _ => intravisit::walk_expr(self, expr),
        }
    }
}

impl LossyEnqueueVisitor<'_, '_> {
    fn enqueue_is_lossy(&self, receiver: &Expr<'_>, message: Option<&Expr<'_>>) -> bool {
        let Some(policy) = self.receiver_lossy_policy(receiver) else {
            return false;
        };
        if policy.all {
            return true;
        }

        let Some(message) = message else {
            return false;
        };
        message_variant(message).is_some_and(|variant| policy.variants.contains(&variant))
    }

    fn receiver_lossy_policy(&self, receiver: &Expr<'_>) -> Option<&LossyPolicy> {
        let receiver_ty = self.cx.typeck_results().expr_ty(receiver).peel_refs();
        let ty::Adt(_, args) = receiver_ty.kind() else {
            return None;
        };
        let message_ty = args.get(0).and_then(|arg| arg.as_type())?;
        let ty::Adt(message, _) = message_ty.peel_refs().kind() else {
            return None;
        };
        self.lossy_messages.get(&message.did())
    }
}

fn message_variant(expr: &Expr<'_>) -> Option<Symbol> {
    match expr.kind {
        ExprKind::Struct(qpath, ..) => qpath_name(*qpath),
        ExprKind::Path(qpath) => qpath_name(qpath),
        ExprKind::Call(callee, _) => {
            if let ExprKind::Path(qpath) = callee.kind {
                qpath_name(qpath)
            } else {
                None
            }
        }
        ExprKind::Block(block, _) => block.expr.and_then(message_variant),
        _ => None,
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
