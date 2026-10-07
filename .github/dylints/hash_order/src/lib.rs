#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;
extern crate rustc_type_ir;

use rustc_errors::DiagDecorator;
use rustc_hir::{Expr, ExprKind, FieldDef, LetStmt, Node, def::DefKind};
use rustc_lint::{LateContext, LateLintPass, LintContext, LintStore};
use rustc_middle::ty::{self, Clause, GenericArgsRef, Ty};
use rustc_session::{Session, declare_lint, declare_lint_pass};
use rustc_span::{Span, def_id::DefId, sym};
use rustc_type_ir::elaborate::elaborate;

dylint_linting::dylint_library!();

#[allow(clippy::no_mangle_with_rust_abi)]
#[unsafe(no_mangle)]
pub fn register_lints(_: &Session, lint_store: &mut LintStore) {
    lint_store.register_lints(&[HASH_ITERATION, HASH_DROP]);
    lint_store.register_late_pass(|_| Box::new(HashOrder));
}

declare_lint! {
    /// ### What it does
    ///
    /// Detects iteration over a hash collection. The collections are `HashMap` and `HashSet`
    /// from std or hashbrown, hashbrown's `HashTable`, and ahash's `AHashMap` and `AHashSet`.
    /// The lint covers iterating methods such as `iter`, `keys`, `drain`, `retain`, and
    /// `HashTable::get_bucket` (also when passed as function values), `for` loops, and Rayon
    /// parallel iterators. It also covers calls and function values whose `IntoIterator` or
    /// Rayon `IntoParallelIterator` bounds are satisfied by a hash collection, including bounds
    /// of their trait or inherent impl, bounds implied by supertraits, and the items that
    /// `flatten` visits.
    ///
    /// ### Why is this bad?
    ///
    /// A hash collection visits its entries in an order derived from a randomly seeded hasher,
    /// so the order differs between instances and processes. Once that order reaches observable
    /// behavior, such as the messages a loop sends or the values a function returns, the
    /// deterministic runtime no longer reproduces a run from its seed.
    ///
    /// When the order cannot matter, keep the hash collection and expect the lint with the
    /// reason, for example
    /// `#[cfg_attr(dylint_lib = "hash_order", expect(hash_iteration, reason = "..."))]`.
    ///
    /// The lint does not see traversals inside other code. `Debug` formatting, serde
    /// serialization, `Clone`, set operators, wrapper types that forward `IntoIterator`, and
    /// trait implementations whose own bounds require `IntoIterator` visit entries in hash
    /// order too.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// let scores: HashMap<u64, u64> = HashMap::new();
    /// for (peer, score) in &scores {
    ///     sender.send((*peer, *score));
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// let scores: BTreeMap<u64, u64> = BTreeMap::new();
    /// for (peer, score) in &scores {
    ///     sender.send((*peer, *score));
    /// }
    /// ```
    pub HASH_ITERATION,
    Deny,
    "iteration over a hash collection"
}

declare_lint! {
    /// ### What it does
    ///
    /// Detects hash collections whose elements wake another task when dropped. The lint
    /// recognizes an element that owns a channel endpoint, an actor mailbox, an owned tokio
    /// mutex guard or permit, an aborter, or an acknowledgement, directly or through its
    /// fields, enum variants, type arguments, tuples, and arrays. Values behind `Arc` or `Rc`
    /// count, since the collection may hold their last strong reference. Values behind `Weak`
    /// do not count.
    ///
    /// The lint reports struct and enum fields whose type holds such a collection, also inside
    /// tuples, arrays, and the type arguments of wrappers such as `Arc<Mutex<_>>` or
    /// `Option<_>`. It also reports a `let` whose initializer is a call that creates one, with
    /// an associated function of the collection such as `HashMap::new` or `Default::default`,
    /// or with `collect`.
    ///
    /// ### Why is this bad?
    ///
    /// Dropping, clearing, or retaining a hash collection drops its elements in hash order,
    /// which differs between instances and processes. Each dropped endpoint wakes the task
    /// waiting on the other end, and the deterministic runtime polls woken tasks in an order
    /// derived from their wake order. A run then no longer reproduces from its seed.
    ///
    /// When no task can be waiting on the elements, keep the hash collection and expect the
    /// lint with the reason, for example
    /// `#[cfg_attr(dylint_lib = "hash_order", expect(hash_drop, reason = "..."))]`.
    ///
    /// Other `let` initializers are not reported, such as a call to another function, a `?`,
    /// block, or branch expression, or a wrapper as in `Arc::new(Mutex::new(HashMap::new()))`.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// struct Waiters {
    ///     pending: HashMap<u64, oneshot::Sender<()>>,
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// struct Waiters {
    ///     pending: BTreeMap<u64, oneshot::Sender<()>>,
    /// }
    /// ```
    pub HASH_DROP,
    Deny,
    "hash collection of values whose drop wakes another task"
}

declare_lint_pass!(HashOrder => [HASH_ITERATION, HASH_DROP]);

/// Hash collections, by crate and type name.
const HASH_COLLECTIONS: &[(&str, &[&str])] = &[
    ("ahash", &["AHashMap", "AHashSet"]),
    ("hashbrown", &["HashMap", "HashSet", "HashTable"]),
    ("std", &["HashMap", "HashSet"]),
];

/// Methods of hash collections that visit entries in hash order, including the accessors that
/// address a `HashTable` by bucket index.
const ITERATING: &[&str] = &[
    "difference",
    "drain",
    "extract_if",
    "get_bucket",
    "get_bucket_entry",
    "get_bucket_entry_unchecked",
    "get_bucket_mut",
    "get_bucket_unchecked",
    "get_bucket_unchecked_mut",
    "intersection",
    "into_keys",
    "into_values",
    "iter",
    "iter_buckets",
    "iter_hash",
    "iter_hash_buckets",
    "iter_hash_mut",
    "iter_mut",
    "keys",
    "retain",
    "symmetric_difference",
    "union",
    "unsafe_iter",
    "values",
    "values_mut",
];

/// Rayon traits whose methods visit a collection in parallel, splitting it in table order.
const PARALLEL: &[&str] = &[
    "IntoParallelIterator",
    "IntoParallelRefIterator",
    "IntoParallelRefMutIterator",
    "ParallelDrainFull",
];

/// Types whose drop wakes another task, by crate and type name. These are channel endpoints,
/// actor mailboxes, owned tokio mutex guards and permits, aborters, and acknowledgements.
const WAKERS: &[(&str, &[&str])] = &[
    (
        "commonware_actor",
        &[
            "Receiver",
            "Sender",
            "UnreliableReceiver",
            "UnreliableSender",
        ],
    ),
    (
        "commonware_utils",
        &["Aborter", "Exact", "Receiver", "Sender"],
    ),
    (
        "futures_channel",
        &["Receiver", "Sender", "UnboundedReceiver", "UnboundedSender"],
    ),
    (
        "tokio",
        &[
            "OwnedMutexGuard",
            "OwnedPermit",
            "OwnedSemaphorePermit",
            "Receiver",
            "Sender",
            "UnboundedReceiver",
            "UnboundedSender",
        ],
    ),
];

/// Handles that never drop their contents, by crate and type name.
const NON_OWNING: &[(&str, &[&str])] = &[("alloc", &["Weak"])];

/// Returns whether the type definition `did` appears in `types`.
fn listed(cx: &LateContext<'_>, did: DefId, types: &[(&str, &[&str])]) -> bool {
    let krate = cx.tcx.crate_name(did.krate);
    let name = cx.tcx.item_name(did);
    types
        .iter()
        .any(|(owner, names)| *owner == krate.as_str() && names.contains(&name.as_str()))
}

fn is_hash_collection(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    matches!(ty.peel_refs().kind(), ty::Adt(adt, _) if listed(cx, adt.did(), HASH_COLLECTIONS))
}

/// Returns whether a bound on `trait_id` lets code visit the implementing collection:
/// `IntoIterator` or a Rayon parallel iteration trait.
fn iterating_trait(cx: &LateContext<'_>, trait_id: DefId) -> bool {
    cx.tcx.is_diagnostic_item(sym::IntoIterator, trait_id)
        || (cx.tcx.crate_name(trait_id.krate).as_str() == "rayon"
            && PARALLEL.contains(&cx.tcx.item_name(trait_id).as_str()))
}

/// Returns the hash collection that a call to `def_id` visits through an iterating method of
/// the collection.
fn iterated_by_method<'tcx>(
    cx: &LateContext<'tcx>,
    def_id: DefId,
    generic_args: GenericArgsRef<'tcx>,
) -> Option<Ty<'tcx>> {
    let tcx = cx.tcx;
    let impl_id = tcx.impl_of_assoc(def_id)?;
    let self_ty = tcx
        .type_of(impl_id)
        .instantiate(tcx, generic_args)
        .skip_norm_wip();
    (is_hash_collection(cx, self_ty) && ITERATING.contains(&tcx.item_name(def_id).as_str()))
        .then_some(self_ty)
}

/// Returns the hash collections that a call to `def_id` iterates through its iteration bounds
/// (see [`iterating_trait`]), including those of its trait or inherent impl and those implied
/// by supertraits. Examples are the collection of a `for` loop or `IntoIterator::into_iter`,
/// the receiver of a Rayon parallel iterator method, the argument of `extend`, `zip`, or
/// `FromIterator::from_iter`, the receiver of a method whose trait requires `IntoIterator`,
/// and the items that `flatten` visits. Tuple struct and enum variant constructors only move
/// their fields, so their bounds are skipped.
fn iterated_by_bounds<'tcx>(
    cx: &LateContext<'tcx>,
    def_id: DefId,
    generic_args: GenericArgsRef<'tcx>,
) -> Vec<Ty<'tcx>> {
    let tcx = cx.tcx;
    if matches!(tcx.def_kind(def_id), DefKind::Ctor(..)) {
        return Vec::new();
    }
    let predicates: Vec<Clause<'tcx>> = tcx
        .predicates_of(def_id)
        .instantiate(tcx, generic_args)
        .predicates
        .into_iter()
        .map(|clause| clause.skip_norm_wip())
        .collect();
    let mut iterated = Vec::new();
    for clause in elaborate(tcx, predicates) {
        let Some(predicate) = clause.as_trait_clause() else {
            continue;
        };
        if !iterating_trait(cx, predicate.def_id()) {
            continue;
        }
        let self_ty = tcx
            .instantiate_bound_regions_with_erased(predicate)
            .self_ty();
        let self_ty = tcx
            .try_normalize_erasing_regions(
                cx.typing_env().with_post_analysis_normalized(tcx),
                ty::Unnormalized::new_wip(self_ty),
            )
            .unwrap_or(self_ty);
        if is_hash_collection(cx, self_ty) {
            iterated.push(self_ty);
        }
    }
    iterated
}

/// Returns whether dropping a value of type `ty` drops one of [`WAKERS`], which it may own
/// through fields, enum variants, type arguments, tuples, and arrays. `visited` holds the type
/// definitions whose fields were already searched.
fn wakes_on_drop<'tcx>(cx: &LateContext<'tcx>, ty: Ty<'tcx>, visited: &mut Vec<DefId>) -> bool {
    match *ty.kind() {
        ty::Adt(adt, generic_args) => {
            let did = adt.did();
            if listed(cx, did, WAKERS) {
                return true;
            }
            if listed(cx, did, NON_OWNING) {
                return false;
            }
            if generic_args
                .types()
                .any(|arg| wakes_on_drop(cx, arg, visited))
            {
                return true;
            }
            if visited.contains(&did) {
                return false;
            }
            visited.push(did);
            adt.all_fields().any(|field| {
                let field_ty = cx
                    .tcx
                    .type_of(field.did)
                    .instantiate_identity()
                    .skip_norm_wip();
                wakes_on_drop(cx, field_ty, visited)
            })
        }
        ty::Tuple(tys) => tys.iter().any(|ty| wakes_on_drop(cx, ty, visited)),
        ty::Array(ty, _) | ty::Slice(ty) => wakes_on_drop(cx, ty, visited),
        _ => false,
    }
}

/// Returns a hash collection owned by a value of type `ty`, directly or through type
/// arguments, tuples, and arrays, whose elements wake another task when dropped.
fn drop_sensitive<'tcx>(cx: &LateContext<'tcx>, ty: Ty<'tcx>) -> Option<Ty<'tcx>> {
    match *ty.kind() {
        ty::Adt(adt, generic_args) => {
            if listed(cx, adt.did(), HASH_COLLECTIONS)
                && generic_args
                    .types()
                    .any(|arg| wakes_on_drop(cx, arg, &mut Vec::new()))
            {
                return Some(ty);
            }
            generic_args.types().find_map(|arg| drop_sensitive(cx, arg))
        }
        ty::Tuple(tys) => tys.iter().find_map(|ty| drop_sensitive(cx, ty)),
        ty::Array(ty, _) | ty::Slice(ty) => drop_sensitive(cx, ty),
        _ => None,
    }
}

/// Returns whether `expr` creates a hash collection, by calling an associated function of the
/// collection type such as `HashMap::new` or `Default::default`, or by collecting into one.
fn creates_collection(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    let tcx = cx.tcx;
    let typeck = cx.typeck_results();
    let (def_id, generic_args) = match expr.kind {
        ExprKind::Call(callee, _) => match *typeck.expr_ty(callee).kind() {
            ty::FnDef(def_id, generic_args) => (def_id, generic_args),
            _ => return false,
        },
        ExprKind::MethodCall(..) => match typeck.type_dependent_def_id(expr.hir_id) {
            Some(def_id) => (def_id, typeck.node_args(expr.hir_id)),
            None => return false,
        },
        _ => return false,
    };
    let owner = match tcx.impl_of_assoc(def_id) {
        Some(impl_id) => tcx
            .type_of(impl_id)
            .instantiate(tcx, generic_args)
            .skip_norm_wip(),
        None if tcx.trait_of_assoc(def_id).is_some() => generic_args.type_at(0),
        None => return false,
    };
    is_hash_collection(cx, typeck.expr_ty(expr))
        && (is_hash_collection(cx, owner)
            || tcx.is_diagnostic_item(sym::iterator_collect_fn, def_id))
}

fn report_iteration(cx: &LateContext<'_>, span: Span, ty: Ty<'_>) {
    cx.emit_span_lint(
        HASH_ITERATION,
        span.source_callsite(),
        DiagDecorator(|diag| {
            diag.primary_message("iteration over a hash collection");
            diag.note(format!(
                "`{}` visits entries in an order that varies between runs",
                ty.peel_refs()
            ));
            diag.help(
                "use `BTreeMap` or `BTreeSet`, or expect the lint with a reason if the order cannot matter",
            );
        }),
    );
}

fn report_drop(cx: &LateContext<'_>, span: Span, ty: Ty<'_>) {
    cx.emit_span_lint(
        HASH_DROP,
        span.source_callsite(),
        DiagDecorator(|diag| {
            diag.primary_message("hash collection of values whose drop wakes another task");
            diag.note(format!(
                "`{ty}` drops its elements in an order that varies between runs"
            ));
            diag.help("use `BTreeMap` or `BTreeSet`");
        }),
    );
}

impl<'tcx> LateLintPass<'tcx> for HashOrder {
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
            ExprKind::Path(_) => {
                // A function used as a value, such as `flat_map(HashMap::keys)`. Callees are
                // checked with their call below.
                if matches!(
                    cx.tcx.parent_hir_node(expr.hir_id),
                    Node::Expr(Expr { kind: ExprKind::Call(callee, _), .. })
                        if callee.hir_id == expr.hir_id
                ) {
                    return;
                }
                let ty::FnDef(def_id, generic_args) = *typeck.expr_ty(expr).kind() else {
                    return;
                };
                let iterated = match iterated_by_method(cx, def_id, generic_args) {
                    Some(collection) => vec![collection],
                    None => iterated_by_bounds(cx, def_id, generic_args),
                };
                for collection in iterated {
                    report_iteration(cx, expr.span, collection);
                }
                return;
            }
            _ => return,
        };
        let inputs: Vec<&Expr<'_>> = receiver.into_iter().chain(args).collect();

        // An iterating method of the collection, reported at the whole call.
        if let Some(collection) = iterated_by_method(cx, def_id, generic_args) {
            report_iteration(cx, expr.span, collection);
            return;
        }

        // Hash collections iterated through the call's iteration bounds, such as a `for` loop or
        // `extend`, reported at the matching input (or at the call, as for `flatten`).
        for ty in iterated_by_bounds(cx, def_id, generic_args) {
            let input = inputs.iter().find(|input| {
                cx.tcx
                    .erase_and_anonymize_regions(typeck.expr_ty_adjusted(input))
                    == ty
            });
            report_iteration(cx, input.map_or(expr.span, |input| input.span), ty);
        }
    }

    fn check_field_def(&mut self, cx: &LateContext<'tcx>, field: &'tcx FieldDef<'tcx>) {
        let ty = cx
            .tcx
            .type_of(field.def_id)
            .instantiate_identity()
            .skip_norm_wip();
        if let Some(collection) = drop_sensitive(cx, ty) {
            report_drop(cx, field.ty.span, collection);
        }
    }

    fn check_local(&mut self, cx: &LateContext<'tcx>, local: &'tcx LetStmt<'tcx>) {
        let Some(init) = local.init else {
            return;
        };
        if !creates_collection(cx, init) {
            return;
        }
        if let Some(collection) = drop_sensitive(cx, cx.typeck_results().expr_ty(init)) {
            report_drop(cx, local.span, collection);
        }
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test_examples(env!("CARGO_PKG_NAME"));
}
