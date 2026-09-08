#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_infer;
extern crate rustc_middle;
extern crate rustc_span;
extern crate rustc_trait_selection;

use rustc_errors::DiagDecorator;
use rustc_hir::{
    BorrowKind, Expr, ExprKind, Mutability, Node, QPath, UnOp,
    def::{DefKind, Res},
    def_id::{DefId, LOCAL_CRATE},
};
use rustc_infer::infer::TyCtxtInferExt;
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty::{self, Ty, print::with_forced_trimmed_paths};
use rustc_span::sym;
use rustc_trait_selection::infer::InferCtxtExt;

dylint_linting::impl_late_lint! {
    /// ### What it does
    ///
    /// Detects a `&[u8]` view (`as_ref()`, `as_slice()`, `deref()`, `chunk()`,
    /// `&x[..]`, `&*x`, any of those behind `&mut`, or one `let` away) of a
    /// buffer that implements `bytes::Buf`, or of an owned `Vec<u8>` local or
    /// temporary, passed to a callee parameter bounded directly by `Buf`. The
    /// callee need not decode: only the consumers listed in `SINKS`, which copy
    /// their input outright, are exempt.
    ///
    /// Skips calls to trait methods whose `Self` implements
    /// `commonware_codec::FixedSize`, `--test` compilations, and crates that
    /// link `libfuzzer_sys`. Views taken in another function, inside a macro
    /// body, bound more than one `let` away, or read from a struct field of
    /// type `Vec<u8>` are not followed.
    ///
    /// ### Why is this bad?
    ///
    /// `Buf::copy_to_bytes` on `&[u8]` allocates and copies. On `Bytes` and
    /// `IoBuf` it returns a view: a refcount bump on `Bytes`, a copy-free box
    /// on a pooled or heap `IoBuf`. Every `Bytes`, `IoBuf` and `Lazy` field
    /// the codec reads through a slice is therefore allocated and copied.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// let value = V::decode_cfg(frame.as_ref(), &cfg)?;
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// let value = V::decode_cfg(frame, &cfg)?;
    /// ```
    pub SLICE_DECODE,
    Deny,
    "a slice view of an owned buffer passed where the buffer itself would give the codec views",
    SliceDecode::default()
}

/// Methods that borrow a buffer's contents as a `&[u8]`.
const VIEWS: &[&str] = &["as_ref", "as_slice", "deref", "chunk"];

/// `Buf` consumers, as (crate, item) names, that copy their input outright, so
/// a slice costs nothing there.
const SINKS: &[(&str, &str)] = &[
    ("bytes", "put"),
    ("commonware_coding", "encode"),
    ("commonware_cryptography", "append"),
    ("commonware_cryptography", "commit"),
];

#[derive(Default)]
pub struct SliceDecode {
    /// The traits the lint resolves against. Filled on the first expression
    /// rather than in `check_crate`, so the lint does not depend on pass
    /// scheduling. Left empty for skipped crates, which turns the lint off.
    resolved: Option<Resolved>,
}

/// `bytes::Buf` and `commonware_codec::FixedSize` for the crate under
/// compilation. `buf` is `None` when the crate is skipped or does not link
/// `bytes`, which turns the lint off.
struct Resolved {
    buf: Option<DefId>,
    fixed: Option<DefId>,
}

/// How to hand a buffer over instead of a view of it.
enum Fix {
    /// A `Buf` by value.
    Move,
    /// A `Buf` behind a shared reference, or read from a field.
    Clone,
    /// A `Buf` behind a mutable reference.
    Reborrow,
    /// An owned `Vec<u8>`.
    Convert,
}

impl Fix {
    fn help(&self, name: &str) -> String {
        match self {
            Self::Move => format!(
                "pass `{name}` itself, or `{name}.slice(..)` for a sub-range (`freeze()` a mutable buffer first)"
            ),
            Self::Clone => format!(
                "pass `{name}.clone()`, a refcount bump on `Bytes` and `IoBuf`, or `{name}.slice(..)` for a sub-range"
            ),
            Self::Reborrow => {
                format!("pass `&mut *{name}`: a `&mut impl Buf` is itself a `Buf`")
            }
            Self::Convert => format!(
                "convert once with `Bytes::from({name})` and pass that, or a `slice(..)` of it"
            ),
        }
    }
}

/// Returns the trait named `name` defined in the crate named `krate`, if linked.
fn trait_named(cx: &LateContext<'_>, krate: &str, name: &str) -> Option<DefId> {
    cx.tcx.all_traits_including_private().find(|did| {
        cx.tcx.crate_name(did.krate).as_str() == krate && cx.tcx.item_name(*did).as_str() == name
    })
}

/// Returns true if the compilation links a crate named `name`.
fn links(cx: &LateContext<'_>, name: &str) -> bool {
    cx.tcx
        .crates(())
        .iter()
        .any(|krate| cx.tcx.crate_name(*krate).as_str() == name)
}

/// Returns true if `ty` implements the trait `trait_def_id` in the current
/// parameter environment.
fn implements<'tcx>(cx: &LateContext<'tcx>, ty: Ty<'tcx>, trait_def_id: DefId) -> bool {
    cx.tcx
        .infer_ctxt()
        .build(cx.typing_mode())
        .type_implements_trait(trait_def_id, [ty], cx.param_env)
        .must_apply_modulo_regions()
}

/// Returns true if `ty` is `[u8]`.
fn bytes(ty: Ty<'_>) -> bool {
    matches!(ty.kind(), ty::Slice(elem) if matches!(elem.kind(), ty::Uint(ty::UintTy::U8)))
}

/// Returns true if `input`, a callee parameter type with references peeled, is
/// a generic parameter that `callee` bounds directly by `bytes::Buf`.
fn bounded<'tcx>(cx: &LateContext<'tcx>, callee: DefId, input: Ty<'tcx>, buf: DefId) -> bool {
    if !matches!(input.kind(), ty::Param(_)) {
        return false;
    }
    cx.tcx
        .predicates_of(callee)
        .instantiate_identity(cx.tcx)
        .predicates
        .iter()
        .any(|clause| {
            clause
                .as_trait_clause()
                .is_some_and(|pred| pred.def_id() == buf && pred.self_ty().skip_binder() == input)
        })
}

/// Classifies `e` as a buffer that can be handed over without copying: anything
/// implementing `Buf`, by value or behind a reference, or an owned `Vec<u8>`
/// local or temporary. Returns the fix to suggest. `&[u8]`, arrays, `&Vec<u8>`,
/// `Vec<u8>` fields and `T: AsRef<[u8]>` receivers are genuinely borrowed and
/// return `None`.
fn owned<'tcx>(cx: &LateContext<'tcx>, e: &Expr<'_>, buf: DefId) -> Option<Fix> {
    let ty = cx.typeck_results().expr_ty(e);
    let inner = ty.peel_refs();
    let movable = !ty.is_ref()
        && matches!(
            e.kind,
            ExprKind::Path(..) | ExprKind::Call(..) | ExprKind::MethodCall(..)
        );
    if implements(cx, inner, buf) {
        return Some(match ty.ref_mutability() {
            _ if movable => Fix::Move,
            Some(Mutability::Mut) => Fix::Reborrow,
            _ => Fix::Clone,
        });
    }
    let ty::Adt(adt, args) = inner.kind() else {
        return None;
    };
    let vec_u8 = cx.tcx.is_diagnostic_item(sym::Vec, adt.did())
        && matches!(args.type_at(0).kind(), ty::Uint(ty::UintTy::U8));
    (vec_u8 && movable).then_some(Fix::Convert)
}

/// Returns the buffer that `e` is a `&[u8]` view of, with the fix to suggest,
/// following one `let`. Recurses into a receiver, index base or dereferenced
/// value that is not itself owned, so `&mut buf.as_ref()[cursor..].as_ref()`
/// reaches `buf`.
fn view<'tcx>(
    cx: &LateContext<'tcx>,
    e: &'tcx Expr<'tcx>,
    buf: DefId,
    depth: u8,
) -> Option<(&'tcx Expr<'tcx>, Fix)> {
    let inner = match e.kind {
        ExprKind::AddrOf(BorrowKind::Ref, _, inner) => return view(cx, inner, buf, depth),
        ExprKind::Unary(UnOp::Deref, inner) => inner,
        ExprKind::Index(base, _, _) => base,
        ExprKind::MethodCall(segment, receiver, [], _)
            if VIEWS.contains(&segment.ident.as_str()) =>
        {
            receiver
        }
        ExprKind::Path(QPath::Resolved(None, path)) if depth == 0 => {
            let Res::Local(id) = path.res else {
                return None;
            };
            let Node::LetStmt(local) = cx.tcx.parent_hir_node(id) else {
                return None;
            };
            if local.pat.hir_id != id {
                return None;
            }
            return view(cx, local.init?, buf, 1);
        }
        _ => return None,
    };
    owned(cx, inner, buf)
        .map(|fix| (inner, fix))
        .or_else(|| view(cx, inner, buf, depth))
}

impl<'tcx> LateLintPass<'tcx> for SliceDecode {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let resolved = self.resolved.get_or_insert_with(|| {
            // Test and fuzz code decode from slices deliberately. Under
            // `--all-targets` a library is compiled as a plain `lib` unit,
            // which lints every production expression, and again as a
            // `--test` unit, which only adds fixtures. The fuzz-target
            // binaries link `libfuzzer_sys`, and the fuzz packages that hold
            // their helpers are named `<crate>_fuzz`.
            let skip = cx.sess().is_test_crate()
                || links(cx, "libfuzzer_sys")
                || cx.tcx.crate_name(LOCAL_CRATE).as_str().ends_with("_fuzz");
            if skip {
                return Resolved {
                    buf: None,
                    fixed: None,
                };
            }
            Resolved {
                buf: trait_named(cx, "bytes", "Buf"),
                fixed: trait_named(cx, "commonware_codec", "FixedSize"),
            }
        });
        let Some(buf) = resolved.buf else {
            return;
        };
        let fixed = resolved.fixed;
        if expr.span.from_expansion() {
            return;
        }

        // `T::decode_cfg(..)` and free forwarders are calls. `self.decode(..)`
        // is a method call whose receiver is the first signature input.
        let (callee, callee_hir, args, skip) = match expr.kind {
            ExprKind::Call(callee, args) => {
                let ExprKind::Path(qpath) = &callee.kind else {
                    return;
                };
                let Res::Def(DefKind::AssocFn | DefKind::Fn, did) =
                    cx.qpath_res(qpath, callee.hir_id)
                else {
                    return;
                };
                (did, callee.hir_id, args, 0)
            }
            ExprKind::MethodCall(_, _, args, _) => {
                let Some(did) = cx.typeck_results().type_dependent_def_id(expr.hir_id) else {
                    return;
                };
                (did, expr.hir_id, args, 1)
            }
            _ => return,
        };

        // A consumer that copies its input gains nothing from an owned buffer.
        let krate = cx.tcx.crate_name(callee.krate);
        let item = cx.tcx.item_name(callee);
        if SINKS
            .iter()
            .any(|(k, n)| krate.as_str() == *k && item.as_str() == *n)
        {
            return;
        }
        let sig = cx.tcx.fn_sig(callee).instantiate_identity().skip_binder();

        for (i, arg) in args.iter().enumerate() {
            let Some(input) = sig.inputs().get(i + skip) else {
                break;
            };
            if !bounded(cx, callee, input.peel_refs(), buf) {
                continue;
            }

            // A fixed-size value has O(1) byte fields, so the slice path costs
            // no allocation per message there.
            if let Some(fixed) = fixed {
                if cx.tcx.def_kind(cx.tcx.parent(callee)) == DefKind::Trait {
                    let this = cx.typeck_results().node_args(callee_hir).types().next();
                    if this.is_some_and(|this| implements(cx, this, fixed)) {
                        continue;
                    }
                }
            }

            // Only a `&[u8]` argument is a view. A reborrow such as `&mut *buf`
            // hands over a `Buf` already.
            if !bytes(cx.typeck_results().expr_ty(arg).peel_refs()) {
                continue;
            }
            let Some((source, fix)) = view(cx, arg, buf, 0) else {
                continue;
            };
            let ty = with_forced_trimmed_paths!(
                cx.typeck_results().expr_ty(source).peel_refs().to_string()
            );
            let name = cx
                .sess()
                .source_map()
                .span_to_snippet(source.span)
                .unwrap_or_else(|_| "the buffer".into());
            let source_span = source.span;
            cx.emit_span_lint(
                SLICE_DECODE,
                arg.span,
                DiagDecorator(move |diag| {
                    diag.primary_message(format!(
                        "`{ty}` passed to a `Buf` parameter as a `&[u8]` view"
                    ));
                    diag.span_label(source_span, "view of this buffer");
                    diag.help(
                        "a `&[u8]` cannot hand out views of its storage, so every `Bytes`, `IoBuf` and `Lazy` the codec reads from it is allocated and copied",
                    );
                    diag.help(fix.help(&name));
                }),
            );
        }
    }
}

#[test]
fn ui() {
    // The fixture is an example target so it links the real `bytes` and
    // `commonware_codec` crates. `dylint_testing` recovers the fixture's
    // `--extern` flags from a verbose `cargo build`, whose `rustc` lines it
    // cannot match through a `RUSTC_WRAPPER`.
    std::env::remove_var("RUSTC_WRAPPER");
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "main");
}
