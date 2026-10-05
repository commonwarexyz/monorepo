#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;
extern crate rustc_type_ir;

use rustc_errors::{Applicability, DiagDecorator};
use rustc_hir::{
    GenericBound, Generics, ImplItem, Item, ItemKind, Node, TraitItem, TraitItemKind,
    WherePredicateKind, def::DefKind,
};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty::{self, Clause, TyCtxt};
use rustc_span::{
    Span,
    def_id::{DefId, LocalDefId},
};
use rustc_type_ir::elaborate::elaborate;

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Detects a generic bound that other bounds already imply: a supertrait of
    /// another bound on the same item or its enclosing impl or trait, or a bound
    /// that an associated type already declares.
    ///
    /// ### Why is this bad?
    ///
    /// The bound restates what the compiler already assumes. Removing it changes
    /// neither the types the item accepts nor what its body may assume.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// impl<K: Ord + Eq + Write> Write for BTreeSet<K> {}
    /// impl<G: Read> Read for Setup<G> where G::Cfg: Clone {}
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// impl<K: Ord + Write> Write for BTreeSet<K> {}
    /// impl<G: Read> Read for Setup<G> {}
    /// ```
    pub IMPLIED_BOUNDS,
    Deny,
    "bound implied by other bounds"
}

/// Why a bound is implied.
enum Reason<'tcx> {
    /// Elaborating another bound of the same item produces it.
    Own(Clause<'tcx>),
    /// Elaborating a bound of the enclosing impl or trait produces it.
    Parent(Clause<'tcx>),
    /// The associated type declares it.
    Declared(DefId),
}

/// Where a bound is written.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Site {
    /// Bound `bound` of predicate `predicate` (an inline bound list or a where
    /// clause predicate).
    Predicate { predicate: usize, bound: usize },
    /// Bound `bound` of the supertrait or associated type bound list.
    List { bound: usize },
}

/// Returns the span that removes element `i` of `spans` with one adjacent
/// separator, given which elements `gone` removes. Some element must stay.
///
/// An element followed by one that stays takes the separator after it. The
/// others take the separator before them. Spans of removed elements never
/// overlap.
fn separated(spans: &[Span], i: usize, gone: impl Fn(usize) -> bool) -> Span {
    if (i + 1..spans.len()).any(|j| !gone(j)) {
        spans[i].to(spans[i + 1].shrink_to_lo())
    } else {
        spans[i].with_lo(spans[i - 1].hi())
    }
}

/// The written bounds of an item.
struct Written<'a, 'hir> {
    generics: Option<&'a Generics<'hir>>,
    list: &'a [GenericBound<'hir>],
}

impl Written<'_, '_> {
    fn generics(&self) -> &Generics<'_> {
        self.generics.expect("predicate site without generics")
    }

    /// Returns the site of the bound written at `span`.
    fn locate(&self, span: Span) -> Option<Site> {
        if let Some(generics) = self.generics {
            for (predicate, p) in generics.predicates.iter().enumerate() {
                let WherePredicateKind::BoundPredicate(p) = p.kind else {
                    continue;
                };
                if let Some(bound) = p.bounds.iter().position(|b| b.span() == span) {
                    return Some(Site::Predicate { predicate, bound });
                }
            }
        }
        let bound = self.list.iter().position(|b| b.span() == span)?;
        Some(Site::List { bound })
    }

    /// Returns true if `removed` contains every bound of predicate `predicate`.
    fn whole(&self, predicate: usize, removed: &[Site]) -> bool {
        let WherePredicateKind::BoundPredicate(p) = self.generics().predicates[predicate].kind
        else {
            return false;
        };
        !p.bounds.is_empty()
            && (0..p.bounds.len())
                .all(|bound| removed.contains(&Site::Predicate { predicate, bound }))
    }

    /// Returns the span that removes the bound at `site` when every bound in
    /// `removed` (which includes `site`) is removed. Suggestions for the bounds
    /// of one item never overlap.
    fn removal(&self, site: Site, removed: &[Site]) -> Option<Span> {
        match site {
            Site::Predicate { predicate, bound } => {
                if self.whole(predicate, removed) {
                    // The first bound removes the whole predicate.
                    return (bound == 0)
                        .then(|| self.predicate_removal(predicate, removed))
                        .flatten();
                }
                let spans: Vec<Span> = self.generics().predicates[predicate]
                    .kind
                    .bounds()
                    .iter()
                    .map(|b| b.span())
                    .collect();
                Some(separated(&spans, bound, |b| {
                    removed.contains(&Site::Predicate {
                        predicate,
                        bound: b,
                    })
                }))
            }
            Site::List { bound } => {
                let gone = |b| removed.contains(&Site::List { bound: b });
                // A bound list keeps its colon, so it cannot drop every bound.
                if (0..self.list.len()).all(gone) {
                    return None;
                }
                let spans: Vec<Span> = self.list.iter().map(|b| b.span()).collect();
                Some(separated(&spans, bound, gone))
            }
        }
    }

    /// Returns the span that removes predicate `predicate`, every bound of which
    /// is removed. Suggestions for the predicates of one item never overlap.
    fn predicate_removal(&self, predicate: usize, removed: &[Site]) -> Option<Span> {
        let generics = self.generics();
        let predicates = generics.predicates;
        if !predicates[predicate].kind.in_where_clause() {
            return Some(predicates[predicate].span);
        }
        // Where clause predicates follow the inline ones.
        let first = predicates
            .iter()
            .position(|p| p.kind.in_where_clause())
            .expect("where clause predicate not found");
        let gone = |p: usize| self.whole(first + p, removed);
        if (0..predicates.len() - first).all(gone) {
            // The first predicate removes the whole where clause.
            return (predicate == first).then_some(generics.where_clause_span);
        }
        let spans: Vec<Span> = predicates[first..].iter().map(|p| p.span).collect();
        Some(separated(&spans, predicate - first, gone))
    }
}

/// Returns true if `clause`, written at `span`, is a user-written bound to judge.
fn is_candidate<'tcx>(tcx: TyCtxt<'tcx>, clause: Clause<'tcx>, span: Span) -> bool {
    if span.is_dummy() || span.from_expansion() {
        return false;
    }
    match clause.kind().skip_binder() {
        ty::ClauseKind::Trait(pred) => {
            pred.polarity == ty::PredicatePolarity::Positive
                && !tcx.is_sizedness_trait(pred.def_id())
        }
        ty::ClauseKind::TypeOutlives(_) => true,
        _ => false,
    }
}

fn key<'tcx>(tcx: TyCtxt<'tcx>, clause: Clause<'tcx>) -> ty::Binder<'tcx, ty::ClauseKind<'tcx>> {
    tcx.anonymize_bound_vars(clause.kind())
}

/// Returns true if elaborating `from` (itself and its supertraits) produces `target`.
fn elaborates_to<'tcx>(tcx: TyCtxt<'tcx>, from: Clause<'tcx>, target: Clause<'tcx>) -> bool {
    let target = key(tcx, target);
    elaborate(tcx, [from]).any(|c| key(tcx, c) == target)
}

/// Returns the associated type whose declared bounds include `clause`, a bound
/// of `def_id` on a projection.
///
/// Declared bounds only apply to a projection that does not normalize in the
/// item's environment. A where clause on a trait with type parameters also
/// guides inference, which a declared bound may not.
fn declared<'tcx>(tcx: TyCtxt<'tcx>, def_id: LocalDefId, clause: Clause<'tcx>) -> Option<DefId> {
    let self_ty = match clause.kind().skip_binder() {
        ty::ClauseKind::Trait(pred) => {
            let generic = pred.trait_ref.args[1..]
                .iter()
                .any(|a| !matches!(a.kind(), ty::GenericArgKind::Lifetime(_)));
            if generic {
                return None;
            }
            pred.self_ty()
        }
        ty::ClauseKind::TypeOutlives(pred) => pred.0,
        _ => return None,
    };
    let &ty::Alias(ty::AliasTy {
        kind: ty::Projection { def_id: assoc },
        args,
        ..
    }) = self_ty.kind()
    else {
        return None;
    };
    let target = key(tcx, clause);
    let rigid = tcx
        .param_env(def_id)
        .caller_bounds()
        .iter()
        .any(|c| key(tcx, c) == target);
    let declared = tcx
        .item_bounds(assoc)
        .iter_instantiated(tcx, args)
        .any(|c| key(tcx, c.skip_norm_wip()) == target);
    (rigid && declared).then_some(assoc)
}

/// Returns true if `clause` is a trait bound on `Self` that makes a trait method
/// dyn incompatible.
fn binds_self<'tcx>(tcx: TyCtxt<'tcx>, clause: Clause<'tcx>) -> bool {
    let ty::ClauseKind::Trait(pred) = clause.kind().skip_binder() else {
        return false;
    };
    !tcx.trait_is_auto(pred.def_id())
        && pred
            .trait_ref
            .args
            .iter()
            .any(|a| a.walk().any(|g| g == tcx.types.self_param.into()))
}

/// Reports each bound in `own` that the remaining bounds in `own`, the bounds in
/// `parent`, or an associated type's declared bounds imply. `item` is the item
/// whose predicates `own` holds, or `None` for associated type bounds.
///
/// Bounds are judged in source order and a reported bound no longer implies
/// later ones, so only one of two duplicates is reported.
fn report<'tcx>(
    cx: &LateContext<'tcx>,
    own: &[(Clause<'tcx>, Span)],
    parent: &[Clause<'tcx>],
    item: Option<LocalDefId>,
    written: Written<'_, 'tcx>,
) {
    let tcx = cx.tcx;
    // Removing a bound that carries an associated item constraint (`Trait<Assoc = X>`,
    // `Fn(A) -> B`) also drops the constraint, whose clause lies within its span.
    let constrained = |span: Span| {
        own.iter().any(|&(c, s)| {
            matches!(c.kind().skip_binder(), ty::ClauseKind::Projection(_)) && span.contains(s)
        })
    };
    let trait_method = item.is_some_and(|item| {
        tcx.def_kind(item) == DefKind::AssocFn
            && tcx.def_kind(tcx.local_parent(item)) == DefKind::Trait
    });
    let mut implied: Vec<Option<Reason<'tcx>>> = own.iter().map(|_| None).collect();
    for (i, &(clause, span)) in own.iter().enumerate() {
        if !is_candidate(tcx, clause, span) || constrained(span) {
            continue;
        }
        let reason = item
            .and_then(|item| declared(tcx, item, clause))
            .map(Reason::Declared)
            .or_else(|| {
                own.iter()
                    .zip(&implied)
                    .enumerate()
                    .filter(|&(j, (_, reason))| j != i && reason.is_none())
                    .map(|(_, (&(c, _), _))| c)
                    .find(|&c| elaborates_to(tcx, c, clause))
                    .map(Reason::Own)
            })
            .or_else(|| {
                // A trait method's own bound on `Self` decides whether the trait
                // is dyn compatible, even when a supertrait implies it.
                if trait_method && binds_self(tcx, clause) {
                    return None;
                }
                parent
                    .iter()
                    .copied()
                    .find(|&c| elaborates_to(tcx, c, clause))
                    .map(Reason::Parent)
            });
        implied[i] = reason;
    }
    let sites: Vec<Option<Site>> = own.iter().map(|&(_, span)| written.locate(span)).collect();
    let removed: Vec<Site> = sites
        .iter()
        .zip(&implied)
        .filter_map(|(&site, reason)| reason.as_ref().and(site))
        .collect();
    let source_map = cx.sess().source_map();
    for ((&(clause, span), site), reason) in own.iter().zip(sites).zip(implied) {
        let Some(reason) = reason else {
            continue;
        };
        // Never delete a comment written next to the bound.
        let removal = site
            .and_then(|site| written.removal(site, &removed))
            .filter(|&removal| {
                source_map
                    .span_to_snippet(removal)
                    .is_ok_and(|s| !s.contains("//") && !s.contains("/*"))
            });
        cx.emit_span_lint(
            IMPLIED_BOUNDS,
            span,
            DiagDecorator(move |diag| {
                diag.primary_message(format!("bound `{clause}` is implied by other bounds"));
                match reason {
                    Reason::Own(by) => {
                        diag.note(format!("implied by `{by}`"));
                    }
                    Reason::Parent(by) => {
                        diag.note(format!("implied by `{by}` on the enclosing item"));
                    }
                    Reason::Declared(assoc) => {
                        diag.note(format!(
                            "declared on associated type `{}`",
                            tcx.def_path_str(assoc)
                        ));
                    }
                }
                match removal {
                    Some(removal) => {
                        diag.span_suggestion(
                            removal,
                            "remove this bound",
                            "",
                            Applicability::MachineApplicable,
                        );
                    }
                    None => {
                        diag.help("remove this bound");
                    }
                }
            }),
        );
    }
}

/// Returns true if `def_id` was generated by a macro or derive, which copies
/// the user's bounds with the user's spans.
fn generated(tcx: TyCtxt<'_>, def_id: LocalDefId) -> bool {
    tcx.def_span(def_id).from_expansion()
}

/// Checks the generic predicates (inline bounds, where clauses, and supertraits)
/// of `def_id`.
fn check_predicates(cx: &LateContext<'_>, def_id: LocalDefId) {
    let tcx = cx.tcx;
    if !matches!(
        tcx.def_kind(def_id),
        DefKind::Fn
            | DefKind::AssocFn
            | DefKind::AssocTy
            | DefKind::Impl { .. }
            | DefKind::Struct
            | DefKind::Enum
            | DefKind::Union
            | DefKind::Trait
    ) || generated(tcx, def_id)
    {
        return;
    }
    let predicates = tcx.explicit_predicates_of(def_id);
    let parent: Vec<Clause<'_>> = predicates
        .parent
        .map(|parent| {
            tcx.predicates_of(parent)
                .instantiate_identity(tcx)
                .predicates
                .into_iter()
                .map(|c| c.skip_norm_wip())
                .collect()
        })
        .unwrap_or_default();
    let list = match tcx.hir_node_by_def_id(def_id) {
        Node::Item(Item {
            kind: ItemKind::Trait { bounds, .. },
            ..
        }) => *bounds,
        _ => &[],
    };
    let written = Written {
        generics: tcx.hir_get_generics(def_id),
        list,
    };
    report(cx, predicates.predicates, &parent, Some(def_id), written);
}

/// Checks the declared bounds of the associated type `def_id`.
fn check_item_bounds<'tcx>(
    cx: &LateContext<'tcx>,
    def_id: LocalDefId,
    list: &[GenericBound<'tcx>],
) {
    let tcx = cx.tcx;
    if generated(tcx, def_id) {
        return;
    }
    let own = tcx.explicit_item_bounds(def_id).skip_binder();
    let written = Written {
        generics: None,
        list,
    };
    report(cx, own, &[], None, written);
}

impl<'tcx> LateLintPass<'tcx> for ImpliedBounds {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        check_predicates(cx, item.owner_id.def_id);
    }

    fn check_trait_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx TraitItem<'tcx>) {
        check_predicates(cx, item.owner_id.def_id);
        if let TraitItemKind::Type(bounds, _) = item.kind {
            check_item_bounds(cx, item.owner_id.def_id, bounds);
        }
    }

    fn check_impl_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx ImplItem<'tcx>) {
        check_predicates(cx, item.owner_id.def_id);
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
