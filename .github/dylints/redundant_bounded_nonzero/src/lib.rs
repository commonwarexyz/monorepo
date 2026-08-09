#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_ast;
extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_hir_analysis;
extern crate rustc_middle;
extern crate rustc_span;

use rustc_ast::ast::LitKind;
use rustc_errors::DiagDecorator;
use rustc_hir::{
    AmbigArg, ConstArgKind, GenericArg, PrimTy, QPath, Ty, TyKind,
    def::{DefKind, Res},
    def_id::DefId,
};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty::{
    Const as MiddleConst, ConstKind as MiddleConstKind, Ty as MiddleTy, TyKind as MiddleTyKind,
    Unnormalized,
};
use rustc_span::sym;

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects positive [`commonware_utils::Bounded`] ranges whose inner type is
    /// already a standard-library `NonZero` integer.
    ///
    /// ### Why is this bad?
    ///
    /// A positive lower bound already excludes zero. Nesting a `NonZero` type
    /// duplicates that invariant and complicates construction and extraction.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// type Count = Bounded<NonZeroU32, 1, 100>;
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// type Count = Bounded<u32, 1, 100>;
    /// ```
    pub REDUNDANT_BOUNDED_NONZERO,
    Deny,
    "NonZero inner type duplicates a positive Bounded lower bound"
}

impl<'tcx> LateLintPass<'tcx> for RedundantBoundedNonzero {
    fn check_ty(&mut self, cx: &LateContext<'tcx>, ty: &'tcx Ty<'tcx, AmbigArg>) {
        if ty.span.from_expansion() {
            return;
        }

        let Some((inner_span, inner_is_nonzero, minimum_is_positive)) =
            bounded_info(cx, ty, &[], 0)
        else {
            return;
        };
        if !inner_is_nonzero || !minimum_is_positive {
            return;
        }

        cx.emit_span_lint(
            REDUNDANT_BOUNDED_NONZERO,
            inner_span,
            DiagDecorator(|diag| {
                diag.primary_message(
                    "NonZero is redundant inside a Bounded range with a positive minimum",
                );
                diag.help("use the corresponding primitive integer as the inner type");
            }),
        );
    }
}

const MAX_ALIAS_DEPTH: usize = 32;

#[derive(Clone, Copy)]
struct AliasFrame<'tcx> {
    def_id: DefId,
    arguments: &'tcx [GenericArg<'tcx>],
}

fn bounded_info<'tcx, Unambig>(
    cx: &LateContext<'tcx>,
    ty: &'tcx Ty<'tcx, Unambig>,
    frames: &[AliasFrame<'tcx>],
    depth: usize,
) -> Option<(rustc_span::Span, bool, bool)> {
    if depth > MAX_ALIAS_DEPTH {
        return None;
    }
    let TyKind::Path(qpath) = ty.kind else {
        return None;
    };
    let Res::Def(def_kind, def_id) = cx.qpath_res(&qpath, ty.hir_id) else {
        return None;
    };

    if cx.tcx.def_path_str(def_id) == "commonware_utils::Bounded" {
        let [GenericArg::Type(inner), minimum, _maximum] = path_arguments(qpath)? else {
            return None;
        };
        let inner_is_nonzero = is_nonzero_integer(cx, inner, frames, depth + 1)
            || normalized_hir_type(cx, inner)
                .is_some_and(|inner| is_middle_nonzero_integer(cx, inner, &[], frames, depth + 1));
        return Some((
            inner.span,
            inner_is_nonzero,
            is_positive_minimum(cx, minimum, frames, depth + 1),
        ));
    }
    if def_kind != DefKind::TyAlias {
        return None;
    }

    let arguments = path_arguments(qpath)?;
    if let Some(alias) = local_alias_ty(cx, def_id) {
        let mut nested = frames.to_vec();
        nested.push(AliasFrame { def_id, arguments });
        let (_, inner_is_nonzero, minimum_is_positive) =
            bounded_info(cx, alias, &nested, depth + 1)?;
        return Some((ty.span, inner_is_nonzero, minimum_is_positive));
    }

    let resolved = cx
        .tcx
        .type_of(def_id)
        .instantiate_identity()
        .skip_norm_wip();
    let MiddleTyKind::Adt(definition, bounded_args) = resolved.kind() else {
        return None;
    };
    if cx.tcx.def_path_str(definition.did()) != "commonware_utils::Bounded" {
        return None;
    }
    Some((
        ty.span,
        is_middle_nonzero_integer(cx, bounded_args.type_at(0), arguments, frames, depth + 1),
        match bounded_args.const_at(1).kind() {
            MiddleConstKind::Param(minimum) => arguments
                .get(minimum.index as usize)
                .is_some_and(|minimum| is_positive_minimum(cx, minimum, frames, depth + 1)),
            _ => is_resolved_positive_minimum(bounded_args.const_at(1)),
        },
    ))
}

fn is_nonzero_integer<'tcx, Unambig>(
    cx: &LateContext<'tcx>,
    ty: &'tcx Ty<'tcx, Unambig>,
    frames: &[AliasFrame<'tcx>],
    depth: usize,
) -> bool {
    if depth > MAX_ALIAS_DEPTH {
        return false;
    }
    let TyKind::Path(qpath) = ty.kind else {
        return false;
    };
    match cx.qpath_res(&qpath, ty.hir_id) {
        Res::Def(DefKind::TyParam, def_id) => parameter_argument(cx, def_id, frames)
            .and_then(|(argument, outer)| match argument {
                GenericArg::Type(argument) => {
                    Some(is_nonzero_integer(cx, argument, outer, depth + 1))
                }
                _ => None,
            })
            .unwrap_or(false),
        Res::Def(DefKind::Struct, def_id) if cx.tcx.is_diagnostic_item(sym::NonZero, def_id) => {
            path_arguments(qpath)
                .and_then(|arguments| {
                    arguments.iter().find_map(|argument| match argument {
                        GenericArg::Type(argument) => Some(*argument),
                        _ => None,
                    })
                })
                .is_some_and(|argument| is_unsigned_integer(cx, argument, frames, depth + 1))
        }
        Res::Def(DefKind::TyAlias, def_id) => {
            let arguments = path_arguments(qpath).unwrap_or_default();
            if let Some(alias) = local_alias_ty(cx, def_id) {
                let mut nested = frames.to_vec();
                nested.push(AliasFrame { def_id, arguments });
                if is_nonzero_integer(cx, alias, &nested, depth + 1) {
                    return true;
                }
            }
            let resolved = normalized_type_of(cx, def_id);
            is_middle_nonzero_integer(cx, resolved, arguments, frames, depth + 1)
        }
        _ => false,
    }
}

fn is_middle_nonzero_integer<'tcx>(
    cx: &LateContext<'tcx>,
    ty: MiddleTy<'tcx>,
    use_arguments: &'tcx [GenericArg<'tcx>],
    frames: &[AliasFrame<'tcx>],
    depth: usize,
) -> bool {
    if depth > MAX_ALIAS_DEPTH {
        return false;
    }
    if let MiddleTyKind::Param(parameter) = ty.kind() {
        return use_arguments
            .get(parameter.index as usize)
            .and_then(|argument| match argument {
                GenericArg::Type(argument) => {
                    Some(is_nonzero_integer(cx, argument, frames, depth + 1))
                }
                _ => None,
            })
            .unwrap_or(false);
    }
    let MiddleTyKind::Adt(definition, nonzero_arguments) = ty.kind() else {
        return false;
    };
    if !cx.tcx.is_diagnostic_item(sym::NonZero, definition.did()) {
        return false;
    }
    match nonzero_arguments.type_at(0).kind() {
        MiddleTyKind::Uint(_) => true,
        MiddleTyKind::Param(parameter) => use_arguments
            .get(parameter.index as usize)
            .and_then(|argument| match argument {
                GenericArg::Type(argument) => {
                    Some(is_unsigned_integer(cx, argument, frames, depth + 1))
                }
                _ => None,
            })
            .unwrap_or(false),
        _ => false,
    }
}

fn is_unsigned_integer<'tcx, Unambig>(
    cx: &LateContext<'tcx>,
    ty: &'tcx Ty<'tcx, Unambig>,
    frames: &[AliasFrame<'tcx>],
    depth: usize,
) -> bool {
    if depth > MAX_ALIAS_DEPTH {
        return false;
    }
    let TyKind::Path(qpath) = ty.kind else {
        return false;
    };
    match cx.qpath_res(&qpath, ty.hir_id) {
        Res::PrimTy(PrimTy::Uint(_)) => true,
        Res::Def(DefKind::TyParam, def_id) => parameter_argument(cx, def_id, frames)
            .and_then(|(argument, outer)| match argument {
                GenericArg::Type(argument) => {
                    Some(is_unsigned_integer(cx, argument, outer, depth + 1))
                }
                _ => None,
            })
            .unwrap_or(false),
        Res::Def(DefKind::TyAlias, def_id) => {
            let arguments = path_arguments(qpath).unwrap_or_default();
            if let Some(alias) = local_alias_ty(cx, def_id) {
                let mut nested = frames.to_vec();
                nested.push(AliasFrame { def_id, arguments });
                if is_unsigned_integer(cx, alias, &nested, depth + 1) {
                    return true;
                }
            }
            let resolved = normalized_type_of(cx, def_id);
            match resolved.kind() {
                MiddleTyKind::Uint(_) => true,
                MiddleTyKind::Param(parameter) => arguments
                    .get(parameter.index as usize)
                    .and_then(|argument| match argument {
                        GenericArg::Type(argument) => {
                            Some(is_unsigned_integer(cx, argument, frames, depth + 1))
                        }
                        _ => None,
                    })
                    .unwrap_or(false),
                _ => false,
            }
        }
        _ => false,
    }
}

fn is_positive_minimum<'tcx>(
    cx: &LateContext<'tcx>,
    argument: &'tcx GenericArg<'tcx>,
    frames: &[AliasFrame<'tcx>],
    depth: usize,
) -> bool {
    if depth > MAX_ALIAS_DEPTH {
        return false;
    }
    let GenericArg::Const(argument) = argument else {
        return false;
    };
    match argument.as_unambig_ct().kind {
        ConstArgKind::Literal {
            lit: LitKind::Int(value, _),
            negated: false,
        } => value.get() > 0,
        ConstArgKind::Anon(argument) => cx
            .tcx
            .const_eval_poly(argument.def_id.to_def_id())
            .ok()
            .and_then(|value| value.try_to_scalar_int())
            .map(u32::from)
            .is_some_and(|value| value > 0),
        ConstArgKind::Path(qpath) => {
            let Res::Def(DefKind::ConstParam, def_id) = cx.qpath_res(&qpath, argument.hir_id)
            else {
                return false;
            };
            parameter_argument(cx, def_id, frames).is_some_and(|(argument, outer)| {
                is_positive_minimum(cx, argument, outer, depth + 1)
            })
        }
        _ => false,
    }
}

fn is_resolved_positive_minimum(minimum: MiddleConst<'_>) -> bool {
    minimum
        .try_to_leaf()
        .is_some_and(|minimum| minimum.to_u32() > 0)
}

fn normalized_type_of<'tcx>(cx: &LateContext<'tcx>, def_id: DefId) -> MiddleTy<'tcx> {
    let resolved = cx
        .tcx
        .type_of(def_id)
        .instantiate_identity()
        .skip_norm_wip();
    cx.tcx
        .try_normalize_erasing_regions(cx.typing_env(), Unnormalized::new_wip(resolved))
        .unwrap_or(resolved)
}

fn normalized_hir_type<'tcx>(
    cx: &LateContext<'tcx>,
    ty: &'tcx Ty<'tcx, AmbigArg>,
) -> Option<MiddleTy<'tcx>> {
    let resolved = if let Some(typeck) = cx.maybe_typeck_results() {
        if typeck.hir_owner != ty.hir_id.owner {
            return None;
        }
        typeck.node_type_opt(ty.hir_id)?
    } else {
        rustc_hir_analysis::lower_ty(cx.tcx, ty.as_unambig_ty())
    };
    Some(
        cx.tcx
            .try_normalize_erasing_regions(cx.typing_env(), Unnormalized::new_wip(resolved))
            .unwrap_or(resolved),
    )
}

fn path_arguments<'tcx>(qpath: QPath<'tcx>) -> Option<&'tcx [GenericArg<'tcx>]> {
    match qpath {
        QPath::Resolved(_, path) => path.segments.last(),
        QPath::TypeRelative(_, segment) => Some(segment),
    }
    .and_then(|segment| segment.args)
    .map(|arguments| arguments.args)
}

fn local_alias_ty<'tcx>(cx: &LateContext<'tcx>, def_id: DefId) -> Option<&'tcx Ty<'tcx>> {
    cx.tcx.hir_node_by_def_id(def_id.as_local()?).alias_ty()
}

fn parameter_argument<'a, 'tcx>(
    cx: &LateContext<'tcx>,
    def_id: DefId,
    frames: &'a [AliasFrame<'tcx>],
) -> Option<(&'tcx GenericArg<'tcx>, &'a [AliasFrame<'tcx>])> {
    for (frame_index, frame) in frames.iter().enumerate().rev() {
        let Some(index) = cx
            .tcx
            .generics_of(frame.def_id)
            .param_def_id_to_index(cx.tcx, def_id)
        else {
            continue;
        };
        let argument = frame.arguments.get(index as usize)?;
        return Some((argument, &frames[..frame_index]));
    }
    None
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "main");
}
