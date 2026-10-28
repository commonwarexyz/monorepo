#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use rustc_errors::DiagDecorator;
use rustc_hir::{
    Expr, ExprKind,
    def::{DefKind, Res},
    def_id::{CRATE_DEF_ID, DefId},
};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty;
use rustc_span::{ExpnKind, MacroKind, Span, Symbol, sym};
use std::{
    env,
    path::{Component, Path},
};

dylint_linting::impl_late_lint! {
    /// ### What it does
    ///
    /// Checks that every benchmark binary declares commonware-allocator's
    /// `MiMalloc` as its `#[global_allocator]`. A benchmark is a binary crate whose
    /// root file lies in a `benches` directory of its package, which covers
    /// Cargo's default benchmark location and the `src/<module>/benches/` layout
    /// that the benchmark authoring guide prescribes.
    ///
    /// ### Why is this bad?
    ///
    /// A benchmark measures allocation costs under its global allocator. Without
    /// mimalloc, it measures the system allocator instead of the allocator the
    /// root README recommends for binaries.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// criterion_main!(benches);
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// use commonware_allocator::mimalloc;
    ///
    /// #[global_allocator]
    /// static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);
    ///
    /// criterion_main!(benches);
    /// ```
    pub BENCHMARK_ALLOCATOR,
    Deny,
    "benchmark without commonware-allocator's mimalloc as its global allocator",
    BenchmarkAllocator::default()
}

const MIMALLOC: [&str; 3] = ["commonware_allocator", "mimalloc", "MiMalloc"];
const GLOBAL_ALLOC: [&str; 4] = ["core", "alloc", "global", "GlobalAlloc"];

#[derive(Default)]
struct BenchmarkAllocator {
    /// The static that this crate installs with `#[global_allocator]`.
    global: Option<Global>,
}

struct Global {
    def_id: DefId,
    /// The static's type, or `None` if it is commonware-allocator's `MiMalloc`.
    other: Option<String>,
}

impl<'tcx> LateLintPass<'tcx> for BenchmarkAllocator {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        // `#[global_allocator] static GLOBAL: T = ...;` expands into allocator
        // shims whose bodies call `GlobalAlloc::<method>(&GLOBAL, ...)`.
        let ExprKind::Call(callee, [allocator, ..]) = expr.kind else {
            return;
        };
        let ExpnKind::Macro(MacroKind::Attr, name) = expr.span.ctxt().outer_expn_data().kind else {
            return;
        };
        if name != sym::global_allocator {
            return;
        }
        let ty::FnDef(method, _) = *cx.typeck_results().expr_ty(callee).kind() else {
            return;
        };
        if !cx
            .tcx
            .trait_of_assoc(method)
            .is_some_and(|tr| is_path(cx, tr, &GLOBAL_ALLOC))
        {
            return;
        }
        let ExprKind::AddrOf(_, _, path) = allocator.kind else {
            return;
        };
        let ExprKind::Path(qpath) = &path.kind else {
            return;
        };
        let Res::Def(DefKind::Static { .. }, def_id) = cx.qpath_res(qpath, path.hir_id) else {
            return;
        };
        let ty = cx.typeck_results().expr_ty(path);
        let is_mimalloc = match ty.kind() {
            ty::Adt(adt, _) => is_path(cx, adt.did(), &MIMALLOC),
            _ => false,
        };
        self.global = Some(Global {
            def_id,
            other: (!is_mimalloc).then(|| ty.to_string()),
        });
    }

    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        if !is_benchmark(cx) {
            return;
        }

        let Some(global) = &self.global else {
            cx.emit_span_lint(
                BENCHMARK_ALLOCATOR,
                entry_span(cx),
                DiagDecorator(|diag| {
                    diag.primary_message("benchmark does not declare a global allocator");
                    diag.help(
                        "declare `#[global_allocator] static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);` with `use commonware_allocator::mimalloc;`",
                    );
                }),
            );
            return;
        };
        let Some(ty) = &global.other else {
            return;
        };
        cx.emit_span_lint(
            BENCHMARK_ALLOCATOR,
            cx.tcx.def_span(global.def_id),
            DiagDecorator(|diag| {
                diag.primary_message(format!(
                    "benchmark global allocator is `{ty}`, not `commonware_allocator::mimalloc::MiMalloc`"
                ));
            }),
        );
    }
}

/// Returns whether `def_id`'s definition path is `path`.
fn is_path(cx: &LateContext<'_>, def_id: DefId, path: &[&str]) -> bool {
    cx.get_def_path(def_id)
        .iter()
        .map(Symbol::as_str)
        .eq(path.iter().copied())
}

/// Returns whether the crate is a binary whose root file lies in a `benches`
/// directory of the package Cargo is building.
fn is_benchmark(cx: &LateContext<'_>) -> bool {
    if !cx
        .tcx
        .crate_types()
        .contains(&rustc_session::config::CrateType::Executable)
    {
        return false;
    }
    let Some(root) = cx.sess().io.input.opt_path() else {
        return false;
    };
    let (Ok(manifest_dir), Ok(current_dir)) = (env::var("CARGO_MANIFEST_DIR"), env::current_dir())
    else {
        return false;
    };
    let root = current_dir.join(root);
    let Ok(relative) = root.strip_prefix(Path::new(&manifest_dir)) else {
        return false;
    };
    relative.parent().is_some_and(|dir| {
        dir.components()
            .any(|c| c == Component::Normal("benches".as_ref()))
    })
}

/// Returns the span of `main`, or of the macro call that generates it (such as
/// `criterion_main!`), or the start of the crate root file if there is none.
fn entry_span(cx: &LateContext<'_>) -> Span {
    cx.tcx
        .entry_fn(())
        .map(|(main, _)| cx.tcx.def_span(main).source_callsite())
        .filter(|span| !span.is_dummy())
        .unwrap_or_else(|| cx.tcx.def_span(CRATE_DEF_ID).shrink_to_lo())
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
