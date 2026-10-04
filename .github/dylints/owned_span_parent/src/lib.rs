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
use rustc_span::sym;

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects an owned `tracing::Span` converted into a span ID. This covers span
    /// and event parents such as `info_span!(parent: span, ...)`, `follows_from`
    /// sources, explicit conversions, and helpers that take
    /// `impl Into<Option<Id>>`.
    ///
    /// ### Why is this bad?
    ///
    /// Converting an owned span into its ID drops the handle before the ID is used.
    /// If no other handle is alive at that moment, for example because another task
    /// released its handle concurrently, the span has already closed.
    /// `tracing-subscriber`'s registry then panics while registering a child span,
    /// and an event or `follows_from` link refers to a closed span. Borrowing keeps
    /// the handle alive during the call regardless of who else owns the span.
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
    "owned tracing span converted into a span ID"
}

fn is_adt(cx: &LateContext<'_>, ty: Ty<'_>, crate_name: &str, name: &str) -> bool {
    let ty::Adt(adt, _) = ty.kind() else {
        return false;
    };
    cx.tcx.crate_name(adt.did().krate).as_str() == crate_name
        && cx.tcx.item_name(adt.did()).as_str() == name
}

fn is_option_id(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    let ty::Adt(adt, args) = ty.kind() else {
        return false;
    };
    cx.tcx.is_diagnostic_item(sym::Option, adt.did())
        && is_adt(cx, args.type_at(0), "tracing_core", "Id")
}

impl<'tcx> LateLintPass<'tcx> for OwnedSpanParent {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let typeck = cx.typeck_results();
        let (def_id, generic_args, receiver, args) = match expr.kind {
            ExprKind::Call(callee, args) => {
                let ty::FnDef(def_id, generic_args) = *typeck.expr_ty(callee).kind() else {
                    return;
                };
                (def_id, generic_args, None, args)
            }
            ExprKind::MethodCall(_, receiver, args, _) => {
                let Some(def_id) = typeck.type_dependent_def_id(expr.hir_id) else {
                    return;
                };
                (def_id, typeck.node_args(expr.hir_id), Some(receiver), args)
            }
            _ => return,
        };
        let is_owned_span =
            |input: &Expr<'_>| is_adt(cx, typeck.expr_ty_adjusted(input), "tracing", "Span");
        if !receiver.into_iter().chain(args).any(is_owned_span) {
            return;
        }

        // A call converts an argument into an ID when the argument's parameter is the
        // source of an `Into` or `From` bound that targets `Option<Id>`. Collect
        // those parameters. The argument check below limits the report to owned
        // `tracing::Span` values.
        let predicates = cx.tcx.predicates_of(def_id);
        let declared = predicates.instantiate_identity(cx.tcx).predicates;
        let instantiated = predicates.instantiate(cx.tcx, generic_args).predicates;
        let mut converted = Vec::new();
        for (declared, instantiated) in declared.iter().zip(&instantiated) {
            let (Some(declared), Some(instantiated)) =
                (declared.as_trait_clause(), instantiated.as_trait_clause())
            else {
                continue;
            };
            let declared = declared.skip_binder().trait_ref;
            let instantiated = instantiated.skip_binder().trait_ref;
            let (target, parameter) = if cx.tcx.is_diagnostic_item(sym::Into, instantiated.def_id) {
                (instantiated.args.type_at(1), declared.self_ty())
            } else if cx.tcx.is_diagnostic_item(sym::From, instantiated.def_id) {
                (instantiated.self_ty(), declared.args.type_at(1))
            } else {
                continue;
            };
            if is_option_id(cx, target) {
                converted.push(parameter);
            }
        }

        // Report each argument passed for one of those parameters at its source
        // call site. The loop variable that `#[instrument(follows_from = ...)]`
        // generates is reported at the attribute.
        let inputs = cx
            .tcx
            .fn_sig(def_id)
            .instantiate_identity()
            .skip_binder()
            .inputs();
        for (input, declared) in receiver.into_iter().chain(args).zip(inputs) {
            if !converted.contains(declared) || !is_owned_span(input) {
                continue;
            }
            cx.emit_span_lint(
                OWNED_SPAN_PARENT,
                input.span.source_callsite(),
                DiagDecorator(|diag| {
                    diag.primary_message("owned `Span` converted into a span ID");
                    diag.note("the conversion drops this handle before the ID is used");
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
