#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_ast;
extern crate rustc_hir;
extern crate rustc_span;

use rustc_ast::ast::LitKind;
use rustc_hir::{Expr, ExprKind, Node};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_span::{Span, Symbol};

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects a context method chain where `child` and `with_attribute` use the
    /// same string literal, such as
    /// `context.child("peer").with_attribute("peer", id)`.
    ///
    /// ### Why is this bad?
    ///
    /// Child names identify the component that owns work, while attributes
    /// identify dimensions of that component. Reusing the same field name for
    /// both makes metrics and traces harder to interpret.
    ///
    /// ### Example
    ///
    /// ```rust
    /// let ctx = context.child("peer").with_attribute("peer", peer_id);
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust
    /// let ctx = context.child("peer").with_attribute("public_key", peer_id);
    /// ```
    pub CHILD_ATTRIBUTE_NAME_CONFLICT,
    Deny,
    "child name conflicts with context attribute name"
}

impl<'tcx> LateLintPass<'tcx> for ChildAttributeNameConflict {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if expr.span.from_expansion() {
            return;
        }

        if is_receiver_of_method_call(cx, expr) {
            return;
        }

        check_child_attribute_name_conflict(cx, expr);
    }
}

fn check_child_attribute_name_conflict(cx: &LateContext<'_>, expr: &Expr<'_>) {
    let Some((children, attributes)) = child_and_attributes(expr) else {
        return;
    };

    for attribute in attributes {
        for child in &children {
            if child.value == attribute.value {
                cx.span_lint(CHILD_ATTRIBUTE_NAME_CONFLICT, attribute.span, |diag| {
                    diag.primary_message("child name conflicts with context attribute name");
                    diag.span_help(
                        child.span,
                        "choose a child name for the component and an attribute name for the varying field",
                    );
                });
            }
        }
    }
}

#[derive(Clone, Copy)]
struct StringArg {
    value: Symbol,
    span: Span,
}

fn child_and_attributes(expr: &Expr<'_>) -> Option<(Vec<StringArg>, Vec<StringArg>)> {
    let child = Symbol::intern("child");
    let with_attribute = Symbol::intern("with_attribute");
    let mut children = Vec::new();
    let mut attributes = Vec::new();
    let mut current = expr;

    if !matches!(current.kind, ExprKind::MethodCall(..)) {
        return None;
    }

    while let ExprKind::MethodCall(_, receiver, args, ..) = current.kind {
        if is_method(current, child) {
            if let Some(child) = args.first().and_then(string_arg) {
                children.push(child);
            }
        } else if is_method(current, with_attribute) {
            if let Some(attribute) = args.first().and_then(string_arg) {
                attributes.push(attribute);
            }
        }

        current = receiver;
    }

    (!children.is_empty()).then_some((children, attributes))
}

fn is_receiver_of_method_call(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let Node::Expr(parent) = cx.tcx.parent_hir_node(expr.hir_id) else {
        return false;
    };
    let ExprKind::MethodCall(_, receiver, ..) = parent.kind else {
        return false;
    };

    receiver.hir_id == expr.hir_id
}

fn is_method(expr: &Expr<'_>, method: Symbol) -> bool {
    let ExprKind::MethodCall(segment, ..) = expr.kind else {
        return false;
    };

    segment.ident.name == method
}

fn string_arg(expr: &Expr<'_>) -> Option<StringArg> {
    if let ExprKind::Lit(lit) = expr.kind {
        if let LitKind::Str(value, _) = lit.node {
            return Some(StringArg {
                value,
                span: expr.span,
            });
        }
    }

    None
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
