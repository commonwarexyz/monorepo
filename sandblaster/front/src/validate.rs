//! Subset validation: the global rules of DESIGN.md §3 (and where every
//! other §3 rejection is enforced).
//!
//! | Rule (DESIGN.md) | Enforced in | Kind |
//! | --- | --- | --- |
//! | traits, trait impls, `dyn`, `impl Trait`, non-`Copy` bounds (§3.1) | [`crate::resolve`], [`crate::typeck`] | `trait` |
//! | `static` (§3.1) | [`crate::resolve`] | `static` |
//! | macros other than `proof!`/`unreachable!()` (§3.1) | resolve, typeck | `macro` |
//! | closures, fn pointers (§3.1) | typeck | `closure` |
//! | floats (§3.1) | typeck | `float` |
//! | signed integers except `i32` intrinsic immediates (§3.1) | typeck | `signed` |
//! | `u128`/`i128` (§3.1) | typeck | `wide-int` |
//! | raw pointers, pointer-taking intrinsics (§3.1, §9.2) | typeck | `raw-pointer` |
//! | `&mut` except the `copy_from_slice` statement (§3.1) | typeck | `mut-ref` |
//! | `loop`, `break`, `continue`, labels (§3.1) | typeck | `loop` |
//! | `return`/`?` inside loops (§3.1) | typeck | `control-in-loop` |
//! | unsuffixed literals in `as` operands / shift RHS (§3.6) | typeck | `literal` |
//! | attribute whitelist, `#[allow]` whitelist, `#[inline(always)]` + `#[target_feature]` (§3.1) | typeck, here (module attributes) | `attribute` |
//! | `#![forbid(unsafe_code)]` at the DSL root (§3.1) | here | `forbid-unsafe` |
//! | zero-sized slice element types (§3.2) | here (all HIR types), typeck (generic instantiation) | `zst-slice` |
//! | `pub` fn reachable from the root with an `Irr` binder in its kernel type: any `requires`, a `#[decreases(.., max = C)]` depth hypothesis, a `#[ghost]` parameter; or with `#[refines(.., domain = P)]` (§3.1, §15.2, §15.5) | here | `boundary` |
//! | `pub` generic fn reachable from the root with a type parameter inside a slice element type (host instantiation with a ZST, §3.1) | here | `boundary` |
//! | the boundary is the root's `pub use` list of items, monomorphic (§15.8; [`spec15_gate`], run by the crate path `driver::gates`, not by [`validate`]) | here | `boundary` |
//! | any form of `sandblaster::critical` (§15.8: §15 is always on) | here (module attributes), [`crate::loader`], [`crate::typeck`] | `attribute` |
//! | `#[spec]` modules: ghost, `#[cfg(sandblaster)]` first (§15.1) | here | `attribute` |
//! | `#[proof(refines = f)]` / `#[proof(complete = f)]` pairing (§15.2, §15.5) | here | `law` |
//! | identifier patterns naming consts/unit structs/unit variants (§3.3) | typeck (patterns) | `ident-pattern` |
//! | mutual recursion (§5.6, §7.1) | here (reference graph SCCs) | `recursion` |
//! | non-tail recursion without `decreases(.., max = C)`, `C ≤ 4096` (§3.7) | here | `recursion` |
//! | stack budget: `C × frame` of depth-bounded recursion ≤ [`STACK_BUDGET`] (§3.7) | here ([`check_stack`]) | `recursion` |
//! | intrinsic feature rule (§9.3) | typeck | `feature` |
//! | exec code referring to ghost items (§2) | typeck | `ghost` |
//! | laws and proofs pairing (§4.5), `#[implements]` signatures (§9.3) | here | `law`, `contract` |
//! | a struct with an invariant, a representation relation or a view has only private fields, and at least one (§15.3) | here ([`check_spec15_types`]) | `invariant` |
//! | `Abstract(T)` (§15.3): private fields, no exported constructor, no derived `Debug`, no derived `PartialEq` unless the view is injective, no boundary function exchanging a type that contains `T`, every boundary function over `T` refines through `α_T` | here ([`abstract_reasons`]; used by the elaborator's determinacy verdicts) | — |
//! | `#[proof(view_inj = T)]`: `T` has a closure view, the item takes `(a: T, b: T)`, one per type (§15.2) | here | `law` |
//! | a tail-recursive function with `#[ghost]` parameters (not supported yet) | here | `unsupported` |
//!
//! Self-recursive functions are classified ([`Recursion::Tail`] /
//! [`Recursion::NonTail`]) for the elaborator and the printer.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::diag::{DiagKind, Diagnostic, Diagnostics};
use crate::hir::*;
use crate::resolve::{Def, Resolver};
use crate::typeck::allow_whitelisted;
use crate::visit::{self, Visitor};

/// Stack budget (bytes) of every call tree that contains depth-bounded
/// (non-tail) recursion (§3.7), under the conservative frame model of
/// [`check_stack`]: half of the 2 MiB default stack of a spawned Rust thread
/// (an eighth of the 8 MiB main thread), so the rest of the thread (the
/// host's frames) keeps at least 1 MiB. The model over-approximates real
/// frames by an order of magnitude (QMDB: model ≈ 600 KiB for `verify`'s
/// tree, measured frames ≈ 20–40 KiB in total), so real use stays far below
/// the budget.
pub const STACK_BUDGET: u64 = 1024 * 1024;

/// Fixed per-frame overhead of the frame model (return address, saved
/// registers, alignment, spill slots rustc/LLVM add on their own).
pub const FRAME_OVERHEAD: u64 = 256;

/// Safety factor of the frame model on the counted slot sizes.
pub const FRAME_FACTOR: u64 = 2;

/// Maximum `max` of a depth-bounded recursion (§3.7): no frame is smaller
/// than [`FRAME_OVERHEAD`], so a deeper bound can never meet
/// [`STACK_BUDGET`].
pub const MAX_DEPTH: u64 = STACK_BUDGET / FRAME_OVERHEAD;

/// Nesting depth after which [`is_zst`] stops and answers "zero-sized"
/// (fail closed). Valid Rust types have finite size, so the recursion only
/// goes through inline fields and always terminates; the budget protects the
/// front end from ill-formed (infinitely sized) types rustc rejects later.
pub const LAYOUT_DEPTH: u32 = 1024;

/// Whether `t` may be zero-sized (for the §3.2 slice rule), following rustc's
/// layout rules and erring on the side of "zero-sized" whenever it cannot
/// decide:
///
/// * a tuple or struct is zero-sized iff every field is; an array iff its
///   length is 0 or its element is;
/// * an enum variant with an uninhabited field is *absent* (rustc drops
///   uninhabited variants whose fields are zero-sized; this predicate drops
///   every uninhabited variant, which only answers "zero-sized" more often);
///   an enum is zero-sized iff it has at most one present variant and that
///   variant's fields are zero-sized — so `enum Void {}`, `enum E { A, B(Void) }`
///   and `Option<Void>` are zero-sized;
/// * `Option<T>` is zero-sized iff `T` is uninhabited;
/// * past [`LAYOUT_DEPTH`] levels of nesting, or for an unknown user type,
///   the answer is "zero-sized" (and "uninhabited").
///
/// Type parameters are not zero-sized here (their instantiations are checked
/// at call sites, and a type argument that makes an enum variant uninhabited
/// is itself zero-sized or leaves the enum's size non-zero).
pub fn is_zst(t: &Ty, lookup: &dyn Fn(ItemId) -> Option<ItemKind>) -> bool {
    Layout { lookup, memo: HashMap::new() }.props(t, 0).zst
}

#[derive(Clone, Copy)]
struct LayoutProps {
    /// May be zero-sized.
    zst: bool,
    /// May be uninhabited.
    uninhabited: bool,
}

struct Layout<'a> {
    lookup: &'a dyn Fn(ItemId) -> Option<ItemKind>,
    memo: HashMap<(ItemId, Vec<Ty>), LayoutProps>,
}

impl Layout<'_> {
    fn fields<'t>(&mut self, ts: impl Iterator<Item = &'t Ty>, args: &[Ty], depth: u32) -> LayoutProps {
        let mut out = LayoutProps { zst: true, uninhabited: false };
        for t in ts {
            let p = self.props(&t.subst(args), depth + 1);
            out.zst &= p.zst;
            out.uninhabited |= p.uninhabited;
        }
        out
    }

    fn props(&mut self, t: &Ty, depth: u32) -> LayoutProps {
        const UNKNOWN: LayoutProps = LayoutProps { zst: true, uninhabited: true };
        if depth > LAYOUT_DEPTH {
            return UNKNOWN;
        }
        match t {
            Ty::Never => UNKNOWN,
            Ty::Tuple(ts) => self.fields(ts.iter(), &[], depth),
            Ty::Array(_, 0) => LayoutProps { zst: true, uninhabited: false },
            Ty::Array(t, _) => self.props(t, depth + 1),
            Ty::Option(t) => LayoutProps { zst: self.props(t, depth + 1).uninhabited, uninhabited: false },
            Ty::Adt(id, args) => {
                let key = (*id, args.clone());
                if let Some(p) = self.memo.get(&key) {
                    return *p;
                }
                let p = match (self.lookup)(*id) {
                    Some(ItemKind::Struct(s)) => self.fields(s.fields.iter().map(|f| &f.ty), args, depth),
                    Some(ItemKind::Enum(e)) => {
                        let mut present = 0usize;
                        let mut present_zst = true;
                        for v in &e.variants {
                            let vp = self.fields(v.fields.iter().map(|f| &f.ty), args, depth);
                            if !vp.uninhabited {
                                present += 1;
                                present_zst &= vp.zst;
                            }
                        }
                        LayoutProps { zst: present == 0 || (present == 1 && present_zst), uninhabited: present == 0 }
                    }
                    Some(ItemKind::TypeAlias(a)) => self.props(&a.ty, depth + 1),
                    _ => UNKNOWN,
                };
                self.memo.insert(key, p);
                p
            }
            // scalars, references, slices, vectors, ghost types, parameters,
            // and error types (already reported)
            _ => LayoutProps { zst: false, uninhabited: false },
        }
    }
}

/// Runs every global check, classifies recursion, pairs laws with proofs and
/// fills [`Crate::boundary`] / [`Crate::reachable`].
pub fn validate(krate: &mut Crate, res: &Resolver, diags: &mut Diagnostics) {
    check_module_attrs(res, diags);
    check_zst_slices(krate, diags);
    compute_boundary(krate, res, diags);
    check_recursion(krate, diags);
    check_stack(krate, diags);
    pair_laws(krate, diags);
    pair_spec15_proofs(krate, diags);
    redirect_proof_apps(krate);
    warn_open_goals(krate, diags);
    check_implements(krate, diags);
    check_spec15_types(krate, diags);
}

// ----------------------------------------------------------------------
// §15.3 types: visibility, Abstract(T), ghost parameters
// ----------------------------------------------------------------------

/// The §15.3 rules checked on the HIR (always on):
///
/// * a struct with an invariant, a representation relation or a view (a
///   non-identity abstraction) has only private fields — no `pub`,
///   `pub(crate)` or `pub(super)`: host code cannot forge its values, and
///   inside the crate every construction carries the invariant's obligation
///   (the invariant is part of the kernel type either way; ghost code may
///   read private fields anywhere in the crate);
/// * such a struct has at least one field: a struct without fields (`S;`,
///   `S {}`, `S()`) has a public constructor, so host code could build a
///   value whose invariant was never checked;
/// * a tail-recursive exec function has no `#[ghost]` parameter (its
///   canonical loop would have to carry the ghost binder; not supported
///   yet).
pub fn check_spec15_types(krate: &Crate, diags: &mut Diagnostics) {
    for it in &krate.items {
        match &it.kind {
            ItemKind::Struct(s) => {
                let why = if s.invariant.is_some() {
                    "an invariant (`#[invariant]`)"
                } else if s.represents.is_some() {
                    "a representation relation (`#[represents]`)"
                } else if matches!(s.view, Some(View::Fn { .. })) {
                    "a view (`#[view]`)"
                } else {
                    // no view, or a structural view `#[view(spec::T)]`: every
                    // field maps onto the same-named spec field through its
                    // own (total) field view, so the view holds of every value
                    // and building one field by field breaks nothing
                    // (layered proofs: a model record of a plain data type)
                    continue;
                };
                // a struct without fields (`S;`, `S {}`, `S()`) has no private
                // field: its constructor is public to host code, which could
                // build a value whose invariant was never checked
                if s.fields.is_empty() {
                    let attr = s.invariant.as_ref().and_then(|i| i.props.first().map(|p| p.1)).or(s.represents.as_ref().map(|r| r.span)).or(s.view.as_ref().map(|v| v.span())).unwrap_or(it.span);
                    let lit = match s.shape {
                        Shape::Unit => it.name.clone(),
                        Shape::Tuple => format!("{}()", it.name),
                        Shape::Named => format!("{} {{}}", it.name),
                    };
                    diags.push(
                        Diagnostic::error(DiagKind::Invariant, attr, format!("`{}` has {why} but no fields, so its constructor `{lit}` is public", it.name))
                            .note(format!("host code could build a value with `{lit}` without the invariant ever being checked, and verified code would still rely on it as a fact (DESIGN.md §15.3: fields private, so host code cannot forge values)"))
                            .note(format!("add a private field (e.g. `_sealed: ()`) and build values through a checked constructor (`pub fn new(..) -> Option<{}>`)", it.name)),
                    );
                    continue;
                }
                for (j, f) in s.fields.iter().enumerate() {
                    if f.vis == Vis::Private {
                        continue;
                    }
                    let vis = match f.vis {
                        Vis::Public => "pub",
                        Vis::Crate => "pub(crate)",
                        Vis::Super => "pub(super)",
                        Vis::Private => "",
                    };
                    let fname = f.name.clone().unwrap_or_else(|| j.to_string());
                    diags.push(
                        Diagnostic::error(DiagKind::Invariant, f.span, format!("field `{fname}` of `{}` is `{vis}`, but the type has {why}", it.name))
                            .note("a type with an invariant, a representation relation or a view has only private fields: code outside its module (and host code) must not build or change its values field by field (DESIGN.md §15.3)")
                            .note("remove the visibility; read the field through a method (`fn get(self) -> T`), and build values through checked constructors"),
                    );
                }
            }
            ItemKind::Fn(f) if f.kind == FnKind::Exec && f.recursion == Recursion::Tail && f.params.iter().any(|p| p.ghost) => {
                diags.push(
                    Diagnostic::error(DiagKind::Unsupported, f.sig_span, format!("tail-recursive function `{}` has `#[ghost]` parameters", it.name))
                        .note("the canonical loop of a tail-recursive function cannot carry ghost parameters yet: pass the ghost value to a non-recursive wrapper, or write the loop (DESIGN.md §15.3)"),
                );
            }
            _ => {}
        }
    }
}

/// Whether `t` mentions the user type `id`.
fn mentions_type(t: &Ty, id: ItemId) -> bool {
    let mut found = false;
    t.walk(&mut |x| found |= matches!(x, Ty::Adt(a, _) if *a == id));
    found
}

/// The user types other than `id` that contain `id`: a field type of theirs
/// mentions `id`, or a type that contains it (transitively, through type
/// arguments too).
fn containing_types(krate: &Crate, id: ItemId) -> HashSet<ItemId> {
    let field_tys = |it: &Item| -> Vec<Ty> {
        match &it.kind {
            ItemKind::Struct(s) => s.fields.iter().map(|f| f.ty.clone()).collect(),
            ItemKind::Enum(e) => e.variants.iter().flat_map(|v| v.fields.iter().map(|f| f.ty.clone())).collect(),
            _ => vec![],
        }
    };
    let mut out: HashSet<ItemId> = HashSet::new();
    loop {
        let mut changed = false;
        for it in &krate.items {
            if it.id == id || out.contains(&it.id) {
                continue;
            }
            if field_tys(it).iter().any(|t| mentions_type(t, id) || out.iter().any(|w| mentions_type(t, *w))) {
                out.insert(it.id);
                changed = true;
            }
        }
        if !changed {
            return out;
        }
    }
}

/// Why `T` (item `id`) is not `Abstract(T)` (DESIGN.md §15.3); empty when
/// it is. `view_injective`: its view is known to be injective (then a
/// derived `PartialEq` respects it: `T::eq a b = eqb(α a, α b)`).
///
/// `Abstract(T)`:
/// * every field private; no constructor exported (a public struct
///   without fields, or an enum, is constructible by host code);
/// * `PartialEq` not derived unless view-respecting; `Debug` not derived;
/// * no boundary function exchanges a `T` inside another user type: a
///   parameter or result type that mentions a type containing `T` in its
///   fields (transitively) shows `T`'s representation to the specification
///   of that function (through that type's identity view, or its own view,
///   which may read `T`'s fields) — and so to host code;
/// * every boundary function (a `pub` function reachable from the root)
///   taking or returning `T` (also inside `Option`, tuples, arrays,
///   references) refines through `α_T`: it has `#[refines(s)]`, the
///   signature of `s` mentions neither `T` nor a type containing it (so `s`
///   sees `α(T)` only), and an explicit argument map reads no field of a
///   `T`.
pub fn abstract_reasons(krate: &Crate, id: ItemId, view_injective: bool) -> Vec<String> {
    let it = krate.item(id);
    let reachable = krate.reachable.contains(&id);
    let mut out = Vec::new();
    let derives = match &it.kind {
        ItemKind::Struct(s) => {
            if let Some(f) = s.fields.iter().find(|f| f.vis != Vis::Private) {
                out.push(format!("field `{}` is not private", f.name.clone().unwrap_or_else(|| "0".into())));
            }
            if s.fields.is_empty() && reachable {
                out.push("its constructor is exported (a public struct without fields)".to_string());
            }
            s.derives
        }
        ItemKind::Enum(e) => {
            if reachable {
                out.push("its variants are exported constructors (an enum)".to_string());
            }
            e.derives
        }
        _ => return vec!["not a type".to_string()],
    };
    if derives.partial_eq && !view_injective {
        out.push("it derives `PartialEq`, which compares the representation, not the view".to_string());
    }
    if derives.debug {
        out.push("it derives `Debug`, which shows the representation".to_string());
    }
    let containers = containing_types(krate, id);
    // the first type among `containers` that `t` mentions
    let container_in = |t: &Ty| -> Option<ItemId> {
        let mut found = None;
        t.walk(&mut |x| {
            if let Ty::Adt(a, _) = x
                && found.is_none()
                && containers.contains(a)
            {
                found = Some(*a);
            }
        });
        found
    };
    let name = &it.name;
    for &f in &krate.reachable {
        let fit = krate.item(f);
        match &fit.kind {
            ItemKind::Fn(fd) if host_visible(krate, fit) && fd.kind == FnKind::Exec => {
                let tys: Vec<&Ty> = fd.params.iter().filter(|p| !p.ghost).map(|p| &p.ty).chain(std::iter::once(&fd.ret)).collect();
                if let Some(w) = tys.iter().find_map(|t| container_in(t)) {
                    out.push(format!(
                        "the boundary function `{}` exchanges `{}`, which contains `{name}` in its fields: host code and specifications see `{name}`'s representation through it",
                        fit.path,
                        krate.item(w).path
                    ));
                    continue;
                }
                if !tys.iter().any(|t| mentions_type(t, id)) {
                    continue;
                }
                let Some(r) = &fd.spec.refines else {
                    out.push(format!("the boundary function `{}` takes or returns it without `#[refines]`", fit.path));
                    continue;
                };
                if let Some(sf) = krate.fn_def(r.spec) {
                    let stys: Vec<&Ty> = sf.params.iter().map(|p| &p.ty).chain(std::iter::once(&sf.ret)).collect();
                    if stys.iter().any(|t| mentions_type(t, id) || container_in(t).is_some()) {
                        out.push(format!(
                            "the boundary function `{}` refines `{}`, a specification over the representation of `{name}` (its signature mentions `{name}`, not `α({name})`)",
                            fit.path,
                            krate.item(r.spec).path
                        ));
                        continue;
                    }
                }
                if let Some(args) = &r.args
                    && args.iter().any(|a| reads_fields_of(a, id))
                {
                    out.push(format!("the explicit argument map of `{}`'s `#[refines]` reads a field of `{name}` (its representation, not `α({name})`)", fit.path));
                }
            }
            _ => {}
        }
    }
    out
}

/// Whether `e` reads a field of a value of type `id` (a projection or a
/// pattern over it).
fn reads_fields_of(e: &Expr, id: ItemId) -> bool {
    struct V(ItemId, bool);
    impl Visitor for V {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Field { base, .. } = &e.kind
                && matches!(base.ty.peel_refs(), Ty::Adt(a, _) if *a == self.0)
            {
                self.1 = true;
            }
            visit::walk_expr(self, e);
        }
        fn pat(&mut self, p: &Pat) {
            if let PatKind::Ctor { ctor: Ctor::Struct(a), .. } = &p.kind
                && *a == self.0
            {
                self.1 = true;
            }
            visit::walk_pat(self, p);
        }
    }
    let mut v = V(id, false);
    v.expr(e);
    v.1
}

/// The items reachable from the root's exported items (not its exported
/// modules) through public signatures: the exported items, the struct and
/// enum types of their signatures, public fields and variant fields, the
/// `pub` methods of those types, and so on transitively. Non-ghost, in id
/// order. Each item comes with the exported item through which it was
/// first reached (itself for an exported item).
fn reachable_from_exported_items(krate: &Crate) -> Vec<(ItemId, ItemId)> {
    let mut seen: std::collections::BTreeMap<ItemId, ItemId> = std::collections::BTreeMap::new();
    let mut work: Vec<(ItemId, ItemId)> = krate.boundary.iter().filter_map(|e| if let ExportTarget::Item(id) = e.target { Some((id, id)) } else { None }).collect();
    work.reverse();
    while let Some((id, via)) = work.pop() {
        let it = krate.item(id);
        if it.ghost || seen.contains_key(&id) {
            continue;
        }
        seen.insert(id, via);
        let mut tys: Vec<Ty> = Vec::new();
        match &it.kind {
            ItemKind::Fn(f) => {
                tys.extend(f.params.iter().map(|p| p.ty.clone()));
                tys.push(f.ret.clone());
            }
            ItemKind::Struct(s) => {
                work.extend(s.methods.iter().copied().filter(|m| krate.item(*m).vis == Vis::Public).map(|m| (m, via)));
                tys.extend(s.fields.iter().filter(|f| f.vis == Vis::Public).map(|f| f.ty.clone()));
            }
            ItemKind::Enum(e) => {
                work.extend(e.methods.iter().copied().filter(|m| krate.item(*m).vis == Vis::Public).map(|m| (m, via)));
                tys.extend(e.variants.iter().flat_map(|v| v.fields.iter().map(|f| f.ty.clone())));
            }
            ItemKind::Const(c) => tys.push(c.ty.clone()),
            ItemKind::TypeAlias(a) => tys.push(a.ty.clone()),
        }
        for t in tys {
            t.walk(&mut |x| {
                if let Ty::Adt(a, _) = x {
                    work.push((*a, via));
                }
            });
        }
    }
    seen.into_iter().collect()
}

/// The exported functions of the crate (DESIGN.md §15.1 LR1, the law
/// vocabulary): the functions of the root's `pub use` list, and the `pub`
/// methods of every struct or enum reachable from it through public
/// signatures — the exported types, and also a type that is only returned
/// or taken by an exported function (host code holds its values and calls
/// its `pub` methods whether or not the type is named in the list;
/// [`spec15_gate`] requires it to be named). Invariant and evidence types
/// included.
pub fn exported_functions(krate: &Crate) -> Vec<ItemId> {
    let mut out: Vec<ItemId> = reachable_from_exported_items(krate).into_iter().map(|(id, _)| id).filter(|id| matches!(krate.item(*id).kind, ItemKind::Fn(_))).collect();
    // an exported function is exported even when the walk skipped it
    for e in &krate.boundary {
        if let ExportTarget::Item(id) = e.target
            && matches!(krate.item(id).kind, ItemKind::Fn(_))
        {
            out.push(id);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The host-callable functions of the in-place lifted modules
/// ([`Module::lifted`]): the host's own files, whose functions host code
/// calls directly whether or not the DSL root re-exports them (DESIGN.md
/// §15.5, *Every host-callable function*):
///
/// * every non-private function, free or a method (`pub`, `pub(crate)`,
///   `pub(super)`): the rest of the host crate calls a `pub(crate) fn` as
///   freely as a `pub fn` (`iterator::pos_to_height`), and the methods of
///   a type the DSL root does not re-export as freely as those of one it
///   does. Among them are the impls on primitives, which the lift makes
///   free functions (`u64 == Position` is `u64__eq__Position`,
///   `u64::from(pos)` is `u64__from__Position`; a sealed trait's method on
///   `u16` is the `pub(crate)` function `Trait__u16__m`), and the methods
///   of trait impls;
/// * every private function and private inherent method the host source
///   declares, when the module has a host child module (one the lift
///   leaves out, compiled outside tests): Rust lets a module's
///   descendants call its private items ([`crate::hir::HostAccess`]);
/// * every private function and private inherent method the host source
///   declares that the module's own left-out code calls by name (an
///   `unverified_fns` method, an `unverified_impls` impl, an item outside
///   `items = ..`, a feature-gated item: [`left_out_callers`]).
///
/// They seed [`Crate::reachable`], so they are boundary functions: §15.5
/// requires their contracts and the lock holds them; a precondition or a
/// depth bound of one is a host obligation (stated in the laws file). The
/// lift's own helpers (loop functions) and the private functions of a
/// module without host child modules that no left-out code calls stay
/// internal.
pub fn in_place_host_fns(krate: &Crate) -> Vec<ItemId> {
    krate.items.iter().filter(|it| is_in_place_host_fn(krate, it)).map(|it| it.id).collect()
}

/// `Type::method` of a method item (the instance suffix of a lifted
/// family's type, `Decoder__u16`, dropped), the name of a free function.
fn host_name(it: &Item) -> String {
    let path = it.path.to_string();
    let segs: Vec<&str> = path.split("::").collect();
    match &it.kind {
        ItemKind::Fn(f) if f.owner.is_some() && segs.len() >= 2 => {
            let ty = segs[segs.len() - 2];
            format!("{}::{}", ty.split("__").next().unwrap_or(ty), segs[segs.len() - 1])
        }
        _ => it.name.clone(),
    }
}

/// Whether `it` is one of the [`in_place_host_fns`]: a non-ghost exec
/// function (free or a method) of an in-place lifted module that host code
/// can call — non-private in the host's source, or private with a host
/// child module that sees it.
pub fn is_in_place_host_fn(krate: &Crate, it: &Item) -> bool {
    let ItemKind::Fn(f) = &it.kind else { return false };
    if it.ghost || f.kind != FnKind::Exec {
        return false;
    }
    let Some(m) = krate.modules.get(it.module.0 as usize).filter(|m| m.lifted && !m.ghost) else { return false };
    if f.owner.is_none() && !m.items.contains(&it.id) {
        return false;
    }
    let name = host_name(it);
    let host_private = if f.owner.is_some() { m.host_access.private_methods.contains(&name) } else { it.vis == Vis::Private };
    if host_private { m.host_access.private_callable(&name) || left_out_called(m, it, f, &name) } else { it.vis != Vis::Private }
}

/// Whether the function `it` (`name` as [`host_name`] gives it) is a
/// private function or private inherent method the host source of `m`
/// declares — not a helper the lift split off — that the module's own
/// left-out code calls by name ([`crate::hir::HostAccess::called`]).
fn left_out_called(m: &Module, it: &Item, f: &FnDef, name: &str) -> bool {
    let declared_private = if f.owner.is_some() { m.host_access.private_methods.contains(name) } else { it.vis == Vis::Private && m.host_access.private_fns.contains(name) };
    declared_private && m.host_access.called.contains(name.rsplit("::").next().unwrap_or(name))
}

/// The private functions of the in-place lifted modules that code the
/// lift leaves out calls by name (an `unverified_fns` method, an
/// `unverified_impls` impl, an item outside `items = ..`) and that are not
/// host-callable through a host child module: host code relies on what
/// they return, so they are host-callable functions like the others
/// ([`is_in_place_host_fn`], DESIGN.md §15.5) — boundary functions whose
/// contracts §15.5 requires and the lock holds.
pub fn left_out_callers(krate: &Crate) -> Vec<ItemId> {
    krate
        .items
        .iter()
        .filter(|it| {
            let ItemKind::Fn(f) = &it.kind else { return false };
            let Some(m) = krate.modules.get(it.module.0 as usize).filter(|m| m.lifted && !m.ghost) else { return false };
            let name = host_name(it);
            !it.ghost && f.kind == FnKind::Exec && !m.host_access.private_callable(&name) && left_out_called(m, it, f, &name)
        })
        .map(|it| it.id)
        .collect()
}

/// Whether host code can call item `it` once it is reachable: it is `pub`,
/// or it is one of the [`in_place_host_fns`] (a `pub(crate)` function of
/// the host's own file). The boundary is the reachable items for which
/// this holds.
pub fn host_visible(krate: &Crate, it: &Item) -> bool {
    it.vis == Vis::Public || is_in_place_host_fn(krate, it)
}

/// Every function host code can call (DESIGN.md §15.5 "every function
/// exported from the crate"): the [`exported_functions`], and every other
/// host-visible function of [`Crate::reachable`] ([`host_visible`]) — the
/// verified boundary of §3.1, which also contains the public tree of a
/// `pub mod` at the root (a layout [`spec15_gate`] rejects) and the
/// non-private free functions of the in-place lifted modules
/// ([`in_place_host_fns`]: the impls on primitives among them). Determinacy covers all of them, so no host-callable
/// function escapes it before the gate is on.
pub fn boundary_functions(krate: &Crate) -> Vec<ItemId> {
    let mut out = exported_functions(krate);
    for &id in &krate.reachable {
        let it = krate.item(id);
        if !it.ghost && host_visible(krate, it) && matches!(it.kind, ItemKind::Fn(_)) {
            out.push(id);
        }
    }
    out.sort();
    out.dedup();
    out
}

// ----------------------------------------------------------------------
// module attributes, forbid(unsafe_code)
// ----------------------------------------------------------------------

fn check_module_attrs(res: &Resolver, diags: &mut Diagnostics) {
    for m in &res.mods {
        let sp = |a: &syn::Attribute| crate::span::Span::from_pm2(m.file, syn::spanned::Spanned::span(a));
        let mut forbid = false;
        for a in &m.inner_attrs {
            let path = a.path();
            if path.is_ident("doc") {
                continue;
            }
            if crate::resolve::is_critical_attr(a) {
                diags.push(crate::resolve::critical_diagnostic(sp(a)));
                continue;
            }
            if path.is_ident("forbid") {
                let ok = a.parse_args_with(syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated).map(|l| l.iter().all(|p| p.is_ident("unsafe_code"))).unwrap_or(false);
                if ok {
                    forbid = true;
                    continue;
                }
            }
            if path.is_ident("allow") {
                if let Ok(l) = a.parse_args_with(syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated) {
                    for p in l {
                        let n = quote::ToTokens::to_token_stream(&p).to_string().replace(' ', "");
                        if !allow_whitelisted(&n) {
                            diags.push(Diagnostic::error(DiagKind::Attribute, sp(a), format!("`#![allow({n})]` is not allowed")).note("only `dead_code`, `unused_*`, `non_snake_case`, `non_camel_case_types`, `non_upper_case_globals` and `clippy::*` (DESIGN.md §3.1)"));
                        }
                    }
                }
                continue;
            }
            let n = quote::ToTokens::to_token_stream(path).to_string().replace(' ', "");
            diags.push(Diagnostic::error(DiagKind::Attribute, sp(a), format!("inner attribute `#![{n}]` is not allowed")).note("allowed inner attributes: docs, `#![forbid(unsafe_code)]`, whitelisted `#![allow(..)]`"));
        }
        let mut seen_cfg_sandblaster = false;
        for a in &m.decl_attrs {
            let path = a.path();
            if path.is_ident("cfg") {
                seen_cfg_sandblaster |= matches!(a.parse_args::<syn::Meta>(), Ok(syn::Meta::Path(p)) if p.is_ident("sandblaster"));
                continue;
            }
            if path.is_ident("doc") || path.is_ident("path") {
                continue;
            }
            if crate::resolve::is_critical_attr(a) {
                diags.push(crate::resolve::critical_diagnostic(sp(a)));
                continue;
            }
            if crate::resolve::decl_is_bridges(std::slice::from_ref(a)) {
                if !matches!(a.meta, syn::Meta::Path(_)) {
                    diags.error(DiagKind::Attribute, sp(a), "`#[bridges]` on a module takes no arguments");
                }
                if !m.ghost {
                    diags.push(Diagnostic::error(DiagKind::Attribute, sp(a), "a `#[bridges]` module must be ghost (a module of lemmas, inside the ghost standard library or declared `#[cfg(sandblaster)]`)"));
                }
                continue;
            }
            if crate::resolve::decl_is_model(std::slice::from_ref(a)) {
                if !matches!(a.meta, syn::Meta::Path(_)) {
                    diags.error(DiagKind::Attribute, sp(a), "`#[model]` on a module takes no arguments");
                }
                let own_cfg = m.decl_attrs.iter().any(|x| x.path().is_ident("cfg") && matches!(x.parse_args::<syn::Meta>(), Ok(syn::Meta::Path(p)) if p.is_ident("sandblaster")));
                if !m.ghost {
                    diags.push(
                        Diagnostic::error(DiagKind::Attribute, sp(a), "a `#[model]` module must be ghost: declare it `#[cfg(sandblaster)] #[model] mod m;`")
                            .note("a model is proof text: its functions are evaluated by the kernel and erased from the build"),
                    );
                } else if own_cfg && !seen_cfg_sandblaster {
                    diags.push(Diagnostic::error(DiagKind::Attribute, sp(a), "write `#[cfg(sandblaster)]` before `#[model]` on a module declaration").note("rustc must strip the declaration before it sees `#[model]`"));
                }
                if m.decl_attrs.iter().any(|x| crate::resolve::decl_is_spec(std::slice::from_ref(x))) {
                    diags.error(DiagKind::Attribute, sp(a), "a module is either `#[spec]` (the specification) or `#[model]` (proof text shaped like the code), not both");
                }
                continue;
            }
            if crate::resolve::decl_is_spec(std::slice::from_ref(a)) {
                if !matches!(a.meta, syn::Meta::Path(_)) {
                    diags.error(DiagKind::Attribute, sp(a), "`#[spec]` on a module takes no arguments");
                }
                let own_cfg = m.decl_attrs.iter().any(|x| x.path().is_ident("cfg") && matches!(x.parse_args::<syn::Meta>(), Ok(syn::Meta::Path(p)) if p.is_ident("sandblaster")));
                if !m.ghost {
                    diags.push(
                        Diagnostic::error(DiagKind::Attribute, sp(a), "a `#[spec]` module must be ghost: declare it `#[cfg(sandblaster)] #[spec] mod m;`")
                            .note("spec functions are evaluated by the kernel and erased from the build (DESIGN.md §15.1)"),
                    );
                } else if own_cfg && !seen_cfg_sandblaster {
                    diags.push(
                        Diagnostic::error(DiagKind::Attribute, sp(a), "write `#[cfg(sandblaster)]` before `#[spec]` on a module declaration")
                            .note("rustc must strip the declaration before it expands `#[spec]` (attribute macros on `mod m;` are unstable; DESIGN.md §15.1)"),
                    );
                }
                continue;
            }
            if path.is_ident("allow") {
                if let Ok(l) = a.parse_args_with(syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated) {
                    for p in l {
                        let n = quote::ToTokens::to_token_stream(&p).to_string().replace(' ', "");
                        if !allow_whitelisted(&n) {
                            diags.error(DiagKind::Attribute, sp(a), format!("`#[allow({n})]` is not allowed"));
                        }
                    }
                }
                continue;
            }
            let n = quote::ToTokens::to_token_stream(path).to_string().replace(' ', "");
            diags.error(DiagKind::Attribute, sp(a), format!("attribute `#[{n}]` is not allowed on modules"));
        }
        if m.parent.is_none() && !forbid {
            diags.push(
                Diagnostic::error(DiagKind::ForbidUnsafe, m.span, "the DSL root must start with `#![forbid(unsafe_code)]`")
                    .note("it protects baseline builds of the raw sources; generated code carries `#[deny(unsafe_code)]` instead (DESIGN.md §2, §3.1)"),
            );
        }
    }
}

// ----------------------------------------------------------------------
// zero-sized slices
// ----------------------------------------------------------------------

struct ZstCheck<'a> {
    lookup: &'a dyn Fn(ItemId) -> Option<ItemKind>,
    names: &'a dyn Fn(&Ty) -> String,
    diags: &'a mut Diagnostics,
    seen: HashSet<(crate::span::Span, String)>,
}

impl ZstCheck<'_> {
    fn ty(&mut self, t: &Ty, span: crate::span::Span) {
        let mut bad = None;
        t.walk(&mut |x| {
            if let Ty::Slice(e) = x
                && bad.is_none() && is_zst(e, self.lookup) {
                    bad = Some((**e).clone());
                }
        });
        if let Some(e) = bad {
            let s = (self.names)(&e);
            if self.seen.insert((span, s.clone())) {
                self.diags.push(
                    Diagnostic::error(DiagKind::ZstSlice, span, format!("slices of the zero-sized type `{s}` are not supported"))
                        .note("Rust bounds `len · size_of::<T>()` by `isize::MAX`, which does not bound the length of a slice of a zero-sized type (DESIGN.md §3.2)"),
                );
            }
        }
    }
}

impl Visitor for ZstCheck<'_> {
    fn expr(&mut self, e: &Expr) {
        self.ty(&e.ty, e.span);
        visit::walk_expr(self, e);
    }
    fn pat(&mut self, p: &Pat) {
        self.ty(&p.ty, p.span);
        visit::walk_pat(self, p);
    }
}

fn check_zst_slices(krate: &Crate, diags: &mut Diagnostics) {
    let lookup = |id: ItemId| krate.items.get(id.0 as usize).map(|i| i.kind.clone());
    let names = |t: &Ty| krate.ty_str(t);
    let mut c = ZstCheck { lookup: &lookup, names: &names, diags, seen: HashSet::new() };
    for it in &krate.items {
        match &it.kind {
            ItemKind::Struct(s) => s.fields.iter().for_each(|f| c.ty(&f.ty, f.span)),
            ItemKind::Enum(e) => e.variants.iter().flat_map(|v| v.fields.iter()).for_each(|f| c.ty(&f.ty, f.span)),
            ItemKind::Const(k) => {
                c.ty(&k.ty, it.span);
                c.expr(&k.init);
            }
            ItemKind::TypeAlias(a) => c.ty(&a.ty, it.span),
            ItemKind::Fn(f) => {
                for p in &f.params {
                    c.ty(&p.ty, p.span);
                }
                c.ty(&f.ret, f.sig_span);
                for l in &f.locals {
                    c.ty(&l.ty, l.span);
                }
                visit::walk_fn(&mut c, f);
                visit::walk_fn_spec(&mut c, &f.spec);
                for ex in &f.spec.examples {
                    ex.locals.iter().for_each(|l| c.ty(&l.ty, l.span));
                }
            }
        }
        visit::walk_type_spec(&mut c, &it.kind);
    }
}

// ----------------------------------------------------------------------
// boundary
// ----------------------------------------------------------------------

fn compute_boundary(krate: &mut Crate, res: &Resolver, diags: &mut Diagnostics) {
    // exports of the root
    let mut exports = Vec::new();
    for pn in res.public_names(ModId(0)) {
        if pn.ghost {
            continue;
        }
        let target = match pn.def {
            Def::Item(id) if !krate.item(id).ghost => ExportTarget::Item(id),
            Def::Mod(m) if !krate.module(m).ghost => ExportTarget::Module(m),
            _ => continue,
        };
        if !exports.iter().any(|e: &Export| e.name == pn.name) {
            exports.push(Export { name: pn.name, target, span: pn.span, via_use: pn.import });
        }
    }
    // reachable items: public paths from the root, then pub methods of types
    // whose values are reachable
    let mut items: BTreeSet<ItemId> = BTreeSet::new();
    let mut mods_done: HashSet<ModId> = HashSet::new();
    let mut work: Vec<Def> = exports
        .iter()
        .map(|e| match e.target {
            ExportTarget::Item(i) => Def::Item(i),
            ExportTarget::Module(m) => Def::Mod(m),
        })
        .collect();
    // the host's own files (in place): host code calls their non-private
    // free functions and impls on primitives directly, exported or not
    work.extend(in_place_host_fns(krate).into_iter().map(Def::Item));
    while let Some(d) = work.pop() {
        match d {
            Def::Item(id) => {
                if !items.insert(id) {
                    continue;
                }
                let it = krate.item(id);
                let tys: Vec<Ty> = match &it.kind {
                    ItemKind::Fn(f) => {
                        let mut v: Vec<Ty> = f.params.iter().map(|p| p.ty.clone()).collect();
                        v.push(f.ret.clone());
                        v
                    }
                    ItemKind::Struct(s) => {
                        for m in &s.methods {
                            if krate.item(*m).vis == Vis::Public {
                                work.push(Def::Item(*m));
                            }
                        }
                        s.fields.iter().filter(|f| f.vis == Vis::Public).map(|f| f.ty.clone()).collect()
                    }
                    ItemKind::Enum(e) => {
                        for m in &e.methods {
                            if krate.item(*m).vis == Vis::Public {
                                work.push(Def::Item(*m));
                            }
                        }
                        e.variants.iter().flat_map(|v| v.fields.iter().map(|f| f.ty.clone())).collect()
                    }
                    ItemKind::Const(c) => vec![c.ty.clone()],
                    ItemKind::TypeAlias(a) => vec![a.ty.clone()],
                };
                for t in tys {
                    t.walk(&mut |x| {
                        if let Ty::Adt(a, _) = x {
                            work.push(Def::Item(*a));
                        }
                    });
                }
            }
            Def::Mod(m) => {
                if !mods_done.insert(m) {
                    continue;
                }
                for pn in res.public_names(m) {
                    if !pn.ghost {
                        work.push(pn.def);
                    }
                }
            }
            _ => {}
        }
    }
    let mut reachable = Vec::new();
    for id in items {
        let it = krate.item(id);
        if it.ghost {
            continue;
        }
        reachable.push(id);
        if let ItemKind::Fn(f) = &it.kind
            && host_visible(krate, it)
        {
            // a lifted function's `requires` and depth bound are host
            // obligations (listed in the record of a crate verified in
            // place), not boundary errors
            let lifted = krate.modules.get(it.module.0 as usize).is_some_and(|m| m.lifted);
            check_boundary_fn(krate, it, f, lifted, diags);
        }
    }
    krate.boundary = exports;
    krate.reachable = reachable;
}

/// The live boundary rules of §3.1 for a `pub` function reachable from the
/// DSL root: its kernel type has no `Irr` binder, it has no refinement
/// domain, and host instantiation of its type parameters cannot form a
/// zero-sized-type slice.
fn check_boundary_fn(krate: &Crate, it: &Item, f: &FnDef, lifted: bool, diags: &mut Diagnostics) {
    let hint = "remove `pub` (e.g. `pub(crate)`) and export a total wrapper that establishes it";
    for b in f.irr_binders() {
        let d = match b {
            // a lifted function's `requires` and depth bound are host
            // obligations (listed in the record of a crate verified in place;
            // the lock holds them, and only the laws file may state them on a
            // locked item: `surface::attached_proof_file_errors`)
            IrrBinder::Requires | IrrBinder::DepthBound if lifted => continue,
            IrrBinder::Requires => Diagnostic::error(DiagKind::Boundary, f.sig_span, format!("public function `{}` with `requires` is reachable from the DSL root", it.name))
                .note(format!("the verified boundary must be total: a boundary function's kernel type has no `Irr` binders; {hint}, or make the function total (DESIGN.md §3.1, §15.5)")),
            IrrBinder::DepthBound => {
                let max = f.decreases.as_ref().and_then(|d| d.max).unwrap_or(0);
                Diagnostic::error(DiagKind::Boundary, f.sig_span, format!("public function `{}` with a recursion depth bound (`#[decreases(.., max = {max})]`) is reachable from the DSL root", it.name))
                    .note(format!("the bound is a hidden precondition (`h_depth : measure ≤ {max}`, an `Irr` binder) that host code could violate, breaking the stack obligation of §3.7"))
                    .note(format!("{hint} (DESIGN.md §3.1)"))
            }
            IrrBinder::GhostParam => Diagnostic::error(DiagKind::Boundary, f.sig_span, format!("public function `{}` with `#[ghost]` parameters is reachable from the DSL root", it.name))
                .note(format!("ghost parameters are `Irr` binders that host code cannot supply; {hint} (DESIGN.md §3.1, §15.3)")),
        };
        diags.push(d);
    }
    if let Some(r) = &f.spec.refines
        && let Some(d) = &r.domain
    {
        diags.push(
            Diagnostic::error(DiagKind::Boundary, d.span, format!("public function `{}` reachable from the DSL root refines its spec only on a `domain`", it.name))
                .note("boundary refinements are total: write a total spec plus a law relating it to the standard on its domain; `domain = P` is for internal functions (DESIGN.md §15.2)"),
        );
    }
    if !f.generics.is_empty()
        && let Some(p) = param_in_slice_fn(krate, f)
    {
        diags.push(
            Diagnostic::error(DiagKind::Boundary, f.sig_span, format!("public generic function `{}` reachable from the DSL root has its type parameter `{p}` inside a slice element type", it.name))
                .note(format!("rustc instantiates exported generics at host call sites, where the zero-sized-type rule of §3.2 is never checked: with `{p} = ()` a slice can exceed the model's length bound"))
                .note("export monomorphic instances instead, or keep the generic function non-`pub` (DESIGN.md §3.1)"),
        );
    }
}

/// A type parameter occurring inside a slice element type anywhere in the
/// function (signature, locals, expressions), looking through the fields of
/// user types; its name.
fn param_in_slice_fn(krate: &Crate, f: &FnDef) -> Option<String> {
    struct V<'k> {
        flow: &'k SliceFlow,
        found: Option<String>,
    }
    impl V<'_> {
        fn ty(&mut self, t: &Ty) {
            if self.found.is_none() {
                self.found = self.flow.param_in_slice(t);
            }
        }
    }
    impl Visitor for V<'_> {
        fn expr(&mut self, e: &Expr) {
            self.ty(&e.ty);
            visit::walk_expr(self, e);
        }
        fn pat(&mut self, p: &Pat) {
            self.ty(&p.ty);
            visit::walk_pat(self, p);
        }
    }
    let flow = SliceFlow::new(krate);
    let mut v = V { flow: &flow, found: None };
    for p in &f.params {
        v.ty(&p.ty);
    }
    v.ty(&f.ret);
    for l in &f.locals {
        v.ty(&l.ty);
    }
    visit::walk_fn(&mut v, f);
    v.found
}

/// The first type parameter occurring inside a slice element type of `t`
/// (through the substituted field types of user types).
pub fn param_in_slice(t: &Ty, krate: &Crate) -> Option<String> {
    SliceFlow::new(krate).param_in_slice(t)
}

/// For every user type and type-parameter index, whether that parameter can
/// reach a slice element type through the type's fields (transitively
/// through other user types). It is the least fixed point over the finite
/// set of `(type, parameter index)` pairs, so it needs no traversal budget:
/// many distinct instantiations, or polymorphic recursion through
/// references, can neither cut the search short nor make it diverge.
pub struct SliceFlow {
    flows: HashMap<ItemId, Vec<bool>>,
}

impl SliceFlow {
    pub fn new(krate: &Crate) -> SliceFlow {
        let adts: Vec<(ItemId, usize, Vec<&Ty>)> = krate
            .items
            .iter()
            .filter_map(|it| match &it.kind {
                ItemKind::Struct(s) => Some((it.id, s.generics.len(), s.fields.iter().map(|f| &f.ty).collect())),
                ItemKind::Enum(e) => Some((it.id, e.generics.len(), e.variants.iter().flat_map(|v| v.fields.iter().map(|f| &f.ty)).collect())),
                _ => None,
            })
            .collect();
        let mut flow = SliceFlow { flows: adts.iter().map(|(id, n, _)| (*id, vec![false; *n])).collect() };
        loop {
            let mut changed = false;
            for (id, n, fields) in &adts {
                for j in 0..*n {
                    if !flow.flows[id][j] && fields.iter().any(|t| flow.slot(t, j as u32)) {
                        flow.flows.get_mut(id).expect("adt")[j] = true;
                        changed = true;
                    }
                }
            }
            if !changed {
                return flow;
            }
        }
    }

    /// Whether `Param(j)` reaches a slice element type of `t` (under the
    /// current approximation of `flows`).
    fn slot(&self, t: &Ty, j: u32) -> bool {
        let mentions = |t: &Ty| {
            let mut m = false;
            t.walk(&mut |x| m |= matches!(x, Ty::Param(i, _) if *i == j));
            m
        };
        match t {
            Ty::Slice(e) => mentions(e),
            Ty::Tuple(ts) => ts.iter().any(|t| self.slot(t, j)),
            Ty::Array(t, _) | Ty::Ref(t) | Ty::Option(t) => self.slot(t, j),
            Ty::Adt(id, args) => args.iter().enumerate().any(|(k, a)| mentions(a) && (self.flows_to_slice(*id, k) || self.slot(a, j))),
            _ => false,
        }
    }

    /// Whether parameter `k` of the user type `id` reaches a slice element
    /// type (an unknown type or index answers "yes": fail closed).
    fn flows_to_slice(&self, id: ItemId, k: usize) -> bool {
        self.flows.get(&id).and_then(|v| v.get(k).copied()).unwrap_or(true)
    }

    /// The first type parameter occurring inside a slice element type of
    /// `t` (through the substituted field types of user types).
    pub fn param_in_slice(&self, t: &Ty) -> Option<String> {
        let first_param = |t: &Ty| {
            let mut p = None;
            t.walk(&mut |x| {
                if let (None, Ty::Param(_, n)) = (&p, x) {
                    p = Some(n.clone());
                }
            });
            p
        };
        match t {
            Ty::Slice(e) => first_param(e),
            Ty::Tuple(ts) => ts.iter().find_map(|t| self.param_in_slice(t)),
            Ty::Array(t, _) | Ty::Ref(t) | Ty::Option(t) => self.param_in_slice(t),
            Ty::Adt(id, args) => args.iter().enumerate().find_map(|(k, a)| if self.flows_to_slice(*id, k) { first_param(a) } else { None }.or_else(|| self.param_in_slice(a))),
            _ => None,
        }
    }
}

// ----------------------------------------------------------------------
// the §15.8 boundary gate
// ----------------------------------------------------------------------

/// The §15.8 boundary rules: the first gate of the crate path
/// (`driver::gates::build_crate`), unconditionally, with no flag, profile or
/// environment variable. It runs there rather than in [`validate`], which
/// the front end's stage tests also call on small programs with `pub fn`s
/// at their root (DESIGN.md §15.8, "Where the gates run").
///
/// * The boundary is exactly the DSL root's `pub use` list of items: no
///   `pub mod` at the root, no `pub use` of a module, no `pub` item declared
///   at the root itself (items `pub` inside private modules are not
///   boundary).
/// * Boundary functions (every `pub` function reachable from the root,
///   including `pub` methods of boundary types) are monomorphic.
/// * Every struct or enum reachable from an exported item through public
///   signatures (a parameter, result or public field type) is itself in
///   the root's `pub use` list: host code holds its values and calls its
///   `pub` methods, so they are boundary functions too, and the boundary
///   must be exactly that list.
pub fn spec15_gate(krate: &Crate, diags: &mut Diagnostics) {
    const NOTE: &str = "the boundary is exactly the DSL root's `pub use` list of items: declare modules without `pub` and re-export the API with `pub use m::{..};` (DESIGN.md §3.1, §15.8)";
    for e in &krate.boundary {
        match e.target {
            ExportTarget::Module(m) => {
                let path = krate.module(m).path.to_string();
                let d = if e.via_use {
                    Diagnostic::error(DiagKind::Boundary, e.span, format!("`pub use` of the module `{path}` at the DSL root exports its whole public tree"))
                } else {
                    Diagnostic::error(DiagKind::Boundary, e.span, format!("`pub mod {}` is not allowed at the DSL root", e.name))
                };
                diags.push(d.note(NOTE));
            }
            ExportTarget::Item(id) if !e.via_use => {
                let it = krate.item(id);
                diags.push(Diagnostic::error(DiagKind::Boundary, it.span, format!("`pub` item `{}` declared at the DSL root is not in the root's `pub use` list", it.name)).note("move it into a module and re-export it with `pub use`").note(NOTE));
            }
            ExportTarget::Item(_) => {}
        }
    }
    // types reachable through exported signatures but not exported
    let listed: HashSet<ItemId> = krate.boundary.iter().filter_map(|e| if let ExportTarget::Item(id) = e.target { Some(id) } else { None }).collect();
    for (id, via) in reachable_from_exported_items(krate) {
        let it = krate.item(id);
        if listed.contains(&id) || !matches!(it.kind, ItemKind::Struct(_) | ItemKind::Enum(_)) {
            continue;
        }
        let methods: Vec<String> = match &it.kind {
            ItemKind::Struct(StructDef { methods, .. }) | ItemKind::Enum(EnumDef { methods, .. }) => methods.iter().filter(|m| krate.item(**m).vis == Vis::Public).map(|m| format!("`{}`", krate.item(*m).name)).collect(),
            _ => vec![],
        };
        let also = if methods.is_empty() { String::new() } else { format!(" and calls its `pub` methods ({})", methods.join(", ")) };
        diags.push(
            Diagnostic::error(DiagKind::Boundary, it.span, format!("type `{}` reaches the boundary through `{}` but is not in the root's `pub use` list", it.path, krate.item(via).path))
                .note(format!("host code holds its values{also}: re-export `{}` with `pub use` at the root so the boundary is exactly the root's `pub use` list, and specify every `pub` method it has (DESIGN.md §15.5, §15.8)", it.name))
                .note(NOTE),
        );
    }
    for &id in &krate.reachable {
        let it = krate.item(id);
        if let ItemKind::Fn(f) = &it.kind
            && host_visible(krate, it)
            && !f.generics.is_empty()
        {
            diags.push(
                Diagnostic::error(DiagKind::Boundary, f.sig_span, format!("boundary function `{}` is generic", it.name))
                    .note("boundary functions are monomorphic: export monomorphic instances (DESIGN.md §3.1, §14.2, §15.8)"),
            );
        }
    }
}

// ----------------------------------------------------------------------
// recursion
// ----------------------------------------------------------------------

/// Collects the items an item refers to (calls, constants).
struct Refs {
    out: BTreeSet<ItemId>,
}

impl Visitor for Refs {
    fn expr(&mut self, e: &Expr) {
        match &e.kind {
            ExprKind::Call { callee: Callee::Item(id, _), .. } => {
                self.out.insert(*id);
            }
            ExprKind::Const(id) => {
                self.out.insert(*id);
            }
            _ => {}
        }
        visit::walk_expr(self, e);
    }
}

fn item_refs(it: &Item) -> BTreeSet<ItemId> {
    let mut r = Refs { out: BTreeSet::new() };
    match &it.kind {
        ItemKind::Fn(f) => visit::walk_fn(&mut r, f),
        ItemKind::Const(c) => r.expr(&c.init),
        _ => {}
    }
    r.out
}

/// Tarjan's strongly connected components over the reference graph.
fn sccs(n: usize, edges: &HashMap<usize, Vec<usize>>) -> Vec<Vec<usize>> {
    struct T<'a> {
        edges: &'a HashMap<usize, Vec<usize>>,
        index: Vec<Option<usize>>,
        low: Vec<usize>,
        on: Vec<bool>,
        stack: Vec<usize>,
        next: usize,
        out: Vec<Vec<usize>>,
    }
    fn strong(t: &mut T, v: usize) {
        t.index[v] = Some(t.next);
        t.low[v] = t.next;
        t.next += 1;
        t.stack.push(v);
        t.on[v] = true;
        for &w in t.edges.get(&v).map(|x| x.as_slice()).unwrap_or(&[]) {
            if t.index[w].is_none() {
                strong(t, w);
                t.low[v] = t.low[v].min(t.low[w]);
            } else if t.on[w] {
                t.low[v] = t.low[v].min(t.index[w].unwrap());
            }
        }
        if Some(t.low[v]) == t.index[v] {
            let mut comp = Vec::new();
            loop {
                let w = t.stack.pop().unwrap();
                t.on[w] = false;
                comp.push(w);
                if w == v {
                    break;
                }
            }
            t.out.push(comp);
        }
    }
    let mut t = T { edges, index: vec![None; n], low: vec![0; n], on: vec![false; n], stack: vec![], next: 0, out: vec![] };
    for v in 0..n {
        if t.index[v].is_none() {
            strong(&mut t, v);
        }
    }
    t.out
}

fn check_recursion(krate: &mut Crate, diags: &mut Diagnostics) {
    let n = krate.items.len();
    let mut edges: HashMap<usize, Vec<usize>> = HashMap::new();
    for it in &krate.items {
        let refs = item_refs(it);
        edges.insert(it.id.0 as usize, refs.iter().map(|r| r.0 as usize).collect());
    }
    for comp in sccs(n, &edges) {
        if comp.len() > 1 {
            let mut names: Vec<String> = comp.iter().map(|i| krate.items[*i].path.to_string()).collect();
            names.sort();
            let first = comp.iter().min().copied().unwrap();
            diags.push(
                Diagnostic::error(DiagKind::Recursion, krate.items[first].span, format!("mutual recursion is not supported: {}", names.join(" → ")))
                    .note("only self-recursion is allowed; merge the functions or pass a mode argument (DESIGN.md §5.6)"),
            );
        }
    }
    for i in 0..n {
        let id = ItemId(i as u32);
        let self_ref = edges.get(&i).is_some_and(|e| e.contains(&i));
        if let ItemKind::Const(_) = &krate.items[i].kind {
            if self_ref {
                diags.error(DiagKind::Recursion, krate.items[i].span, "constant refers to itself");
            }
            continue;
        }
        let ItemKind::Fn(f) = &krate.items[i].kind else { continue };
        if !self_ref {
            continue;
        }
        let rec = classify(id, f);
        let (kind, decreases_max, has_decreases, span, name) = (f.kind, f.decreases.as_ref().and_then(|d| d.max), f.decreases.is_some(), f.sig_span, krate.items[i].name.clone());
        if let ItemKind::Fn(f) = &mut krate.items[i].kind {
            f.recursion = rec;
        }
        if kind == FnKind::Exec && rec == Recursion::NonTail {
            match decreases_max {
                None => diags.push(
                    Diagnostic::error(DiagKind::Recursion, span, format!("non-tail recursion in `{name}` needs a depth bound"))
                        .note(format!("write `#[decreases(e, max = C)]` with a literal `C ≤ {MAX_DEPTH}`, or make every recursive call a tail call (DESIGN.md §3.7)")),
                ),
                Some(m) if m > MAX_DEPTH => diags.push(
                    Diagnostic::error(DiagKind::Recursion, span, format!("recursion depth bound {m} exceeds {MAX_DEPTH}"))
                        .note(format!("non-tail recursion is emitted as native recursion; its stack use (depth × frame) must stay within {} KiB and no frame is smaller than {FRAME_OVERHEAD} bytes (DESIGN.md §3.7)", STACK_BUDGET / 1024)),
                ),
                _ => {}
            }
            let _ = has_decreases;
        }
    }
}

// ----------------------------------------------------------------------
// stack budget (§3.7)
// ----------------------------------------------------------------------

/// A conservative size (bytes) of a value of type `t` in a stack slot:
/// every field padded to its alignment, enums and `Option` with an 8-byte
/// tag. `None` when the size depends on a type parameter. Ghost types are
/// erased (0).
pub fn size_of(t: &Ty, krate: &Crate) -> Option<u64> {
    fn align(t: &Ty, krate: &Crate, d: u32) -> u64 {
        if d > 64 {
            return 8;
        }
        match t {
            Ty::Bool => 1,
            Ty::Uint(u) => (u.bits() / 8).max(1) as u64,
            Ty::I32 => 4,
            Ty::Tuple(ts) => ts.iter().map(|x| align(x, krate, d + 1)).max().unwrap_or(1),
            Ty::Array(e, _) | Ty::Slice(e) => align(e, krate, d + 1),
            Ty::Vector(_) => 16,
            _ => 8,
        }
    }
    fn up(n: u64, a: u64) -> u64 {
        n.div_ceil(a.max(1)).saturating_mul(a.max(1))
    }
    fn fields(ts: &[Ty], krate: &Crate, d: u32) -> Option<u64> {
        let mut n = 0u64;
        let mut a = 1u64;
        for t in ts {
            let al = align(t, krate, d + 1);
            a = a.max(al);
            n = up(n, al).saturating_add(go(t, krate, d + 1)?);
        }
        Some(up(n, a))
    }
    fn go(t: &Ty, krate: &Crate, d: u32) -> Option<u64> {
        if d > 64 {
            return None;
        }
        Some(match t {
            Ty::Bool => 1,
            Ty::Uint(u) => (u.bits() / 8).max(1) as u64,
            Ty::I32 => 4,
            Ty::Tuple(ts) => fields(ts, krate, d)?,
            Ty::Array(e, n) => go(e, krate, d + 1)?.saturating_mul(*n),
            // only behind a reference
            Ty::Slice(_) => 0,
            Ty::Ref(inner) => {
                if matches!(**inner, Ty::Slice(_)) {
                    16
                } else {
                    8
                }
            }
            Ty::Option(inner) => go(inner, krate, d + 1)?.saturating_add(8),
            Ty::Adt(id, args) => match krate.items.get(id.0 as usize).map(|i| &i.kind) {
                Some(ItemKind::Struct(s)) => fields(&s.fields.iter().map(|f| f.ty.subst(args)).collect::<Vec<_>>(), krate, d)?,
                Some(ItemKind::Enum(e)) => {
                    let mut m = 0u64;
                    for v in &e.variants {
                        m = m.max(fields(&v.fields.iter().map(|f| f.ty.subst(args)).collect::<Vec<_>>(), krate, d)?);
                    }
                    m.saturating_add(8)
                }
                _ => 8,
            },
            Ty::Param(..) => return None,
            Ty::Vector(v) => {
                let (lane, n) = v.lanes();
                ((lane.bits() / 8) as u64).saturating_mul(n)
            }
            Ty::Int | Ty::Nat | Ty::Seq(_) | Ty::Fn(..) | Ty::Prop | Ty::Proof | Ty::Never | Ty::Error => 0,
        })
    }
    go(t, krate, 0)
}

/// The slot sizes of one exec function (§3.7), before the safety factor:
/// `(all, aggregates)`. `all` counts every parameter, the result, every
/// local it declares and the temporary of every expression node of its body
/// (an unoptimized build gives each its own stack slot); `aggregates` counts
/// only the memory-resident ones among them (arrays, tuples, structs, enums,
/// options, vectors: what stays an `alloca` in optimized code, where scalars
/// live in registers). `proof!` blocks, contracts and loop invariants are
/// erased. `None` when a size depends on a type parameter.
fn frame_slots(f: &FnDef, args: &[Ty], krate: &Crate) -> Option<(u64, u64)> {
    struct V<'k> {
        krate: &'k Crate,
        args: &'k [Ty],
        total: Option<(u64, u64)>,
    }
    impl V<'_> {
        fn add(&mut self, t: &Ty) {
            let t = t.subst(self.args);
            let n = size_of(&t, self.krate);
            let agg = matches!(t, Ty::Array(..) | Ty::Adt(..) | Ty::Option(_) | Ty::Vector(_)) || matches!(&t, Ty::Tuple(ts) if !ts.is_empty());
            self.total = match (self.total, n) {
                (Some((a, g)), Some(b)) => Some((a.saturating_add(b), if agg { g.saturating_add(b) } else { g })),
                _ => None,
            };
        }
    }
    impl Visitor for V<'_> {
        fn expr(&mut self, e: &Expr) {
            self.add(&e.ty);
            visit::walk_expr(self, e);
        }
        fn stmt(&mut self, s: &Stmt) {
            if !matches!(s.kind, StmtKind::Proof(_)) {
                visit::walk_stmt(self, s);
            }
        }
        fn loop_(&mut self, l: &Loop) {
            match &l.kind {
                LoopKind::ForRange { lo, hi, .. } => {
                    self.expr(lo);
                    self.expr(hi);
                }
                LoopKind::While { cond } => self.expr(cond),
            }
            self.block(&l.body);
        }
        fn script(&mut self, _s: &ScriptStmt) {}
    }
    let mut v = V { krate, args, total: Some((0, 0)) };
    for p in &f.params {
        v.add(&p.ty);
    }
    v.add(&f.ret);
    for l in f.locals.iter().filter(|l| !l.ghost) {
        v.add(&l.ty);
    }
    if let FnBody::Exec(b) = &f.body {
        v.expr(b);
    }
    v.total
}

/// Exec calls of a function body (callee, type arguments); contracts and
/// ghost code excluded.
fn exec_calls(f: &FnDef) -> Vec<(ItemId, Vec<Ty>)> {
    struct C(Vec<(ItemId, Vec<Ty>)>);
    impl Visitor for C {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Call { callee: Callee::Item(id, targs), .. } = &e.kind
                && !self.0.iter().any(|(i, t)| i == id && t == targs)
            {
                self.0.push((*id, targs.clone()));
            }
            visit::walk_expr(self, e);
        }
        fn stmt(&mut self, s: &Stmt) {
            if !matches!(s.kind, StmtKind::Proof(_)) {
                visit::walk_stmt(self, s);
            }
        }
        fn script(&mut self, _s: &ScriptStmt) {}
    }
    let mut c = C(vec![]);
    if let FnBody::Exec(b) = &f.body {
        c.expr(b);
    }
    c.0
}

/// Stack estimate of one instantiated exec function.
#[derive(Clone, Copy, Debug)]
struct StackEst {
    /// What inlining this function (and, transitively, its callees) can add
    /// to a caller's frame in optimized code: `aggregates + max inl(callee)`.
    inl: Option<u64>,
    /// Frame of one activation, with what inlined callees can add:
    /// `FRAME_FACTOR × all + FRAME_OVERHEAD + max inl(callee)`.
    frame: Option<u64>,
    /// Worst-case stack of a call: `depth × frame + max stack(callee)`
    /// (`depth` = the recursion bound, 1 otherwise).
    stack: Option<u64>,
    /// Whether the call tree contains depth-bounded recursion.
    recursive: bool,
}

struct StackCx<'k> {
    krate: &'k Crate,
    memo: HashMap<(ItemId, Vec<Ty>), StackEst>,
    active: HashSet<(ItemId, Vec<Ty>)>,
}

impl StackCx<'_> {
    fn est(&mut self, id: ItemId, args: &[Ty]) -> StackEst {
        let key = (id, args.to_vec());
        if let Some(e) = self.memo.get(&key) {
            return *e;
        }
        let zero = StackEst { inl: Some(0), frame: Some(0), stack: Some(0), recursive: false };
        let Some(f) = self.krate.fn_def(id) else { return zero };
        if f.kind != FnKind::Exec || self.krate.item(id).ghost || !self.active.insert(key.clone()) {
            // ghost callees are erased; a cycle is mutual recursion (reported)
            return zero;
        }
        let slots = frame_slots(f, args, self.krate);
        let depth = match (f.recursion, f.decreases.as_ref().and_then(|d| d.max)) {
            (Recursion::NonTail, Some(m)) => m.max(1),
            _ => 1,
        };
        let mut inl_c: Option<u64> = Some(0);
        let mut stack_c: Option<u64> = Some(0);
        let mut recursive = f.recursion == Recursion::NonTail;
        for (c, targs) in exec_calls(f) {
            if c == id {
                continue;
            }
            let targs: Vec<Ty> = targs.iter().map(|t| t.subst(args)).collect();
            let e = self.est(c, &targs);
            recursive |= e.recursive;
            inl_c = inl_c.zip(e.inl).map(|(a, b)| a.max(b));
            stack_c = stack_c.zip(e.stack).map(|(a, b)| a.max(b));
        }
        let own = slots.map(|(all, _)| all.saturating_mul(FRAME_FACTOR).saturating_add(FRAME_OVERHEAD));
        let frame = own.zip(inl_c).map(|(a, b)| a.saturating_add(b));
        let inl = slots.zip(inl_c).map(|((_, agg), b)| agg.saturating_add(b));
        let stack = frame.zip(stack_c).map(|(a, b)| a.saturating_mul(depth).saturating_add(b));
        let e = StackEst { inl, frame, stack, recursive };
        self.active.remove(&key);
        self.memo.insert(key, e);
        e
    }
}

/// The stack-safety obligation of the subset (DESIGN.md §3.7): native
/// recursion must not overflow the stack of the thread it runs on.
///
/// **Frame model.** `frame(f) = FRAME_FACTOR × all(f) + FRAME_OVERHEAD +
/// max inl(callee)`, where `all(f)` ([`frame_slots`]) is the size of every
/// parameter, the result, every local and the temporary of every expression
/// node — an unoptimized build gives each its own slot (and inlines
/// nothing); an optimized build keeps scalars in registers and reuses slots.
/// Inlining can merge a callee into its caller's frame: in optimized code
/// it adds the callee's memory-resident values (`inl(c)` = its aggregate
/// slots plus, transitively, what its own callees can add), and calls in
/// sequence do not overlap (the inliner marks the lifetimes of inlined
/// slots, and stack colouring shares them). The worst-case stack of a call
/// of `f` is `depth(f) × frame(f) + max stack(callee)`, with `depth` the
/// `#[decreases(.., max = C)]` bound of a non-tail recursive function and 1
/// otherwise (tail recursion is emitted as a loop). Measured against
/// rustc 1.98 on QMDB's `merkle::path`: model frame (own part) several KiB,
/// actual frame 272 bytes (debug) / 240 bytes (release).
///
/// **Obligation.** Every exec function whose call tree contains non-tail
/// recursion must have `stack ≤ STACK_BUDGET` (1 MiB, half of the 2 MiB
/// default stack of a spawned thread); a frame that depends on a type
/// parameter cannot be bounded and is rejected under recursion.
pub fn check_stack(krate: &Crate, diags: &mut Diagnostics) {
    let mut cx = StackCx { krate, memo: HashMap::new(), active: HashSet::new() };
    let ids: Vec<ItemId> = krate.items.iter().filter(|it| !it.ghost && matches!(&it.kind, ItemKind::Fn(f) if f.kind == FnKind::Exec)).map(|it| it.id).collect();
    // report at the recursive functions first, then at callers whose own
    // share breaks the budget
    let mut reported: HashSet<ItemId> = HashSet::new();
    for pass in 0..2 {
        for &id in &ids {
            let f = krate.fn_def(id).unwrap();
            let nontail = f.recursion == Recursion::NonTail && f.decreases.as_ref().and_then(|d| d.max).is_some();
            if (pass == 0) != nontail {
                continue;
            }
            let own: Vec<Ty> = f.generics.iter().enumerate().map(|(i, g)| Ty::Param(i as u32, g.name.clone())).collect();
            let e = cx.est(id, &own);
            if !e.recursive {
                continue;
            }
            let calls_reported = exec_calls(f).iter().any(|(c, _)| *c != id && reported.contains(c));
            if calls_reported {
                // the callee's diagnostic covers this tree
                reported.insert(id);
                continue;
            }
            let it = krate.item(id);
            let depth = f.decreases.as_ref().and_then(|d| d.max).filter(|_| nontail).unwrap_or(1);
            match e.stack {
                None => {
                    reported.insert(id);
                    diags.push(
                        Diagnostic::error(DiagKind::Recursion, f.sig_span, format!("cannot bound the stack of `{}`: its call tree contains non-tail recursion and a frame whose size depends on a type parameter", it.name))
                            .note("pass generic values by reference in depth-bounded recursion, or make every recursive call a tail call (DESIGN.md §3.7)"),
                    );
                }
                Some(s) if s > STACK_BUDGET => {
                    reported.insert(id);
                    let msg = if nontail {
                        format!("the depth-bounded recursion of `{}` may overflow the stack: depth {depth} × frame ≈ {} bytes, with callees ≈ {} KiB, exceeds the {} KiB budget", it.name, e.frame.unwrap_or(0), s.div_ceil(1024), STACK_BUDGET / 1024)
                    } else {
                        format!("the call tree of `{}` contains depth-bounded recursion and may use ≈ {} KiB of stack, more than the {} KiB budget", it.name, s.div_ceil(1024), STACK_BUDGET / 1024)
                    };
                    let mut d = Diagnostic::error(DiagKind::Recursion, f.sig_span, msg)
                        .note(format!("frame model: {FRAME_FACTOR} × (parameters + result + locals + one temporary per expression) + {FRAME_OVERHEAD} bytes + the aggregates of callees that may be inlined (DESIGN.md §3.7)"));
                    if nontail {
                        let per = e.frame.unwrap_or(1).max(1);
                        d = d.note(format!("lower the bound (at most ≈ {} for this frame), shrink the frame (pass large values by reference), or make the recursion tail recursive", STACK_BUDGET / per));
                    }
                    diags.push(d);
                }
                _ => {}
            }
        }
    }
}

/// The stack estimate (bytes) of a non-generic exec function under the
/// frame model of [`check_stack`] (for reports and tests).
pub fn stack_estimate(krate: &Crate, id: ItemId) -> Option<u64> {
    let mut cx = StackCx { krate, memo: HashMap::new(), active: HashSet::new() };
    cx.est(id, &[]).stack
}

/// Classifies self-recursion: every self-call in tail position ⇒ `Tail`.
pub fn classify(id: ItemId, f: &FnDef) -> Recursion {
    struct All {
        id: ItemId,
        calls: Vec<*const Expr>,
        tails: HashSet<*const Expr>,
    }
    fn tail(a: &mut All, e: &Expr) {
        match &e.kind {
            ExprKind::Call { callee: Callee::Item(c, _), .. } if *c == a.id => {
                a.tails.insert(e as *const Expr);
            }
            ExprKind::Block(b) => {
                if let Some(t) = &b.tail {
                    tail(a, t);
                }
            }
            ExprKind::If { then, els, .. } => {
                tail(a, then);
                if let Some(x) = els {
                    tail(a, x);
                }
            }
            ExprKind::Match { arms, .. } => arms.iter().for_each(|x| tail(a, &x.body)),
            ExprKind::Return(Some(x)) => tail(a, x),
            _ => {}
        }
    }
    impl Visitor for All {
        fn expr(&mut self, e: &Expr) {
            match &e.kind {
                ExprKind::Call { callee: Callee::Item(c, _), .. } if *c == self.id => self.calls.push(e as *const Expr),
                ExprKind::Return(Some(x)) => {
                    let x: &Expr = x;
                    tail(self, x);
                }
                _ => {}
            }
            visit::walk_expr(self, e);
        }
    }
    let mut a = All { id, calls: vec![], tails: HashSet::new() };
    if let FnBody::Exec(b) | FnBody::Spec(b) = &f.body {
        tail(&mut a, b);
    }
    visit::walk_fn(&mut a, f);
    if a.calls.is_empty() {
        // recursion through contracts or scripts only
        return Recursion::NonTail;
    }
    if a.calls.iter().all(|c| a.tails.contains(c)) {
        Recursion::Tail
    } else {
        Recursion::NonTail
    }
}

// ----------------------------------------------------------------------
// laws and proofs
// ----------------------------------------------------------------------

fn pair_laws(krate: &mut Crate, diags: &mut Diagnostics) {
    let laws: Vec<ItemId> = krate.items.iter().filter(|i| matches!(&i.kind, ItemKind::Fn(f) if f.kind == FnKind::Law)).map(|i| i.id).collect();
    // `#[proof(refines = f)]` / `#[proof(complete = f)]` name their target
    let proofs: Vec<ItemId> = krate.items.iter().filter(|i| matches!(&i.kind, ItemKind::Fn(f) if f.kind == FnKind::Proof && f.spec.proof_of.is_none() && !f.spec.proof_of_unresolved)).map(|i| i.id).collect();
    let mut used: HashMap<ItemId, ItemId> = HashMap::new();
    for p in proofs {
        let pname = krate.item(p).name.clone();
        let cands: Vec<ItemId> = laws.iter().copied().filter(|l| krate.item(*l).name == pname).collect();
        let pspan = krate.item(p).span;
        match cands.as_slice() {
            [] => diags.push(Diagnostic::error(DiagKind::Law, pspan, format!("`#[proof] fn {pname}` does not prove any `#[law]`")).note("a proof must have the same name and parameters as its law (DESIGN.md §4.5)")),
            [l] => {
                if let Some(prev) = used.insert(*l, p) {
                    diags.push(Diagnostic::error(DiagKind::Law, pspan, format!("law `{pname}` has more than one proof")).note_at(krate.item(prev).span, "first proof here"));
                    continue;
                }
                let (lf, pf) = (krate.fn_def(*l).unwrap(), krate.fn_def(p).unwrap());
                let lsig: Vec<(String, Ty)> = lf.params.iter().map(|x| (param_name(lf, x), x.ty.clone())).collect();
                let psig: Vec<(String, Ty)> = pf.params.iter().map(|x| (param_name(pf, x), x.ty.clone())).collect();
                if lsig != psig || lf.generics.len() != pf.generics.len() {
                    diags.push(Diagnostic::error(DiagKind::Law, pspan, format!("`#[proof] fn {pname}` must have the same parameters as its law")).note_at(krate.item(*l).span, "law declared here"));
                }
                if lf.law_proof == Some(LawProof::Inline) {
                    diags.push(Diagnostic::error(DiagKind::Law, pspan, format!("law `{pname}` already has an inline proof")).note_at(krate.item(*l).span, "law declared here"));
                }
                if let ItemKind::Fn(f) = &mut krate.items[l.0 as usize].kind {
                    f.law_proof = Some(LawProof::Item(p));
                }
                if let ItemKind::Fn(f) = &mut krate.items[p.0 as usize].kind {
                    f.proves = Some(*l);
                }
            }
            _ => diags.error(DiagKind::Law, pspan, format!("several laws are named `{pname}`; proofs are matched by name")),
        }
    }
}

/// Pairs `#[proof(refines = f)]` and `#[proof(complete = f)]` items with
/// their exec function `f` (DESIGN.md §15.2, §15.5): `f` must carry
/// `#[refines]` for a refinement proof, the proof has `f`'s parameters (the
/// receiver under any name), and each function has at most one proof of
/// each kind.
fn pair_spec15_proofs(krate: &mut Crate, diags: &mut Diagnostics) {
    let proofs: Vec<(ItemId, ProofOf)> = krate.items.iter().filter_map(|i| match &i.kind {
        ItemKind::Fn(f) if f.kind == FnKind::Proof => f.spec.proof_of.map(|p| (i.id, p)),
        _ => None,
    }).collect();
    let mut view_inj_seen: HashMap<ItemId, ItemId> = HashMap::new();
    for (p, po) in proofs {
        let (pname, pspan) = (krate.item(p).name.clone(), krate.item(p).span);
        if po.kind == ProofKind::ViewInj {
            check_view_inj_proof(krate, p, &po, &mut view_inj_seen, diags);
            continue;
        }
        let Some(t) = krate.fn_def(po.target) else { continue };
        let tname = krate.item(po.target).path.to_string();
        let what = match po.kind {
            ProofKind::Refines => "refines",
            ProofKind::Complete => "complete",
            ProofKind::ViewInj => "view_inj",
        };
        if po.kind == ProofKind::Refines && t.spec.refines.is_none() {
            diags.push(Diagnostic::error(DiagKind::Law, po.span, format!("`#[proof(refines = ..)]` names `{tname}`, which has no `#[refines]`")).note_at(t.sig_span, "add `#[refines(spec::..)]` here (DESIGN.md §15.2)"));
            continue;
        }
        let pf = krate.fn_def(p).unwrap();
        let same = pf.params.len() == t.params.len()
            && pf.params.iter().zip(&t.params).enumerate().all(|(i, (a, b))| {
                // a proof may name a parameter the function leaves unnamed
                // (`_` there, `_x` in the proof) to use it in its script
                let (pn, tn) = (param_name(pf, a), param_name(t, b));
                a.ty == b.ty && (i == 0 && t.receiver.is_some() || pn == tn || (tn == "_" && pn.starts_with('_')))
            })
            && pf.generics.len() == t.generics.len();
        if !same {
            diags.push(Diagnostic::error(DiagKind::Law, pspan, format!("`#[proof({what} = ..)] fn {pname}` must have the parameters of `{tname}`")).note_at(t.sig_span, "the function is declared here (a receiver may be written as a parameter of the same type)"));
        }
        let prev = match po.kind {
            ProofKind::Refines => t.spec.refines_proof,
            ProofKind::Complete => t.spec.complete_proof,
            // checked above (`check_view_inj_proof`)
            ProofKind::ViewInj => None,
        };
        if let Some(prev) = prev {
            diags.push(Diagnostic::error(DiagKind::Law, pspan, format!("`{tname}` has more than one `#[proof({what} = ..)]`")).note_at(krate.item(prev).span, "first proof here"));
            continue;
        }
        if let ItemKind::Fn(f) = &mut krate.items[po.target.0 as usize].kind {
            match po.kind {
                ProofKind::Refines => f.spec.refines_proof = Some(p),
                ProofKind::Complete => f.spec.complete_proof = Some(p),
                ProofKind::ViewInj => {}
            }
        }
    }
}

/// A `#[proof(view_inj = T)]` item (DESIGN.md §15.2, S2): `T` is a struct
/// with a `#[view(|s| e)]` (a structural view is injective by
/// construction); the item has `T`'s type parameters and two parameters
/// of type `T`; one per type.
fn check_view_inj_proof(krate: &Crate, p: ItemId, po: &ProofOf, seen: &mut HashMap<ItemId, ItemId>, diags: &mut Diagnostics) {
    let (pname, pspan) = (krate.item(p).name.clone(), krate.item(p).span);
    let tit = krate.item(po.target);
    let ItemKind::Struct(s) = &tit.kind else { return };
    match &s.view {
        Some(View::Fn { .. }) => {}
        Some(View::Struct { .. }) => {
            diags.push(Diagnostic::error(DiagKind::Law, po.span, format!("`{}` has a structural view (`#[view(spec::T)]`), which is injective by construction: `#[proof(view_inj = ..)]` is not needed", tit.path)));
            return;
        }
        None => {
            diags.push(Diagnostic::error(DiagKind::Law, po.span, format!("`#[proof(view_inj = ..)]` names `{}`, which has no `#[view(|s| ..)]`", tit.path)));
            return;
        }
    }
    let Some(pf) = krate.fn_def(p) else { return };
    let self_ty = Ty::Adt(po.target, s.generics.iter().enumerate().map(|(i, g)| Ty::Param(i as u32, g.name.clone())).collect());
    let ok = pf.generics.len() == s.generics.len() && pf.params.len() == 2 && pf.params.iter().all(|x| x.ty == self_ty && matches!(x.pat.kind, PatKind::Binding { sub: None, .. }));
    if !ok {
        let n = &tit.name;
        diags.push(
            Diagnostic::error(DiagKind::Law, pspan, format!("`#[proof(view_inj = {n})] fn {pname}` must take two values of `{n}`: `fn {pname}(a: {n}, b: {n})`"))
                .note("its steps prove `a.f == b.f` for every field `f`, from `view(a) == view(b)` (a fact) and the invariants of `a` and `b` (DESIGN.md §15.2)"),
        );
    }
    if let Some(prev) = seen.insert(po.target, p) {
        diags.push(Diagnostic::error(DiagKind::Law, pspan, format!("`{}` has more than one `#[proof(view_inj = ..)]`", tit.path)).note_at(krate.item(prev).span, "first proof here"));
    }
}

/// Phase-1 warnings: laws without proofs (open claims) and `todo()` steps
/// (the build fails on both once proofs are checked, §4.4, §4.5).
fn warn_open_goals(krate: &Crate, diags: &mut Diagnostics) {
    fn todos(ss: &[ScriptStmt], out: &mut Vec<crate::span::Span>) {
        for s in ss {
            match &s.kind {
                ScriptKind::Todo => out.push(s.span),
                ScriptKind::Assert { steps: Some(st), .. } | ScriptKind::Cases { steps: st, .. } => todos(st, out),
                ScriptKind::Calc { links, .. } => links.iter().filter_map(|l| l.steps.as_ref()).for_each(|st| todos(st, out)),
                ScriptKind::Match { arms, .. } => arms.iter().for_each(|a| todos(&a.steps, out)),
                ScriptKind::If { then, els, .. } => {
                    todos(then, out);
                    todos(els, out);
                }
                _ => {}
            }
        }
    }
    struct ProofBlocks(Vec<crate::span::Span>);
    impl Visitor for ProofBlocks {
        fn stmt(&mut self, s: &Stmt) {
            if let StmtKind::Proof(ss) = &s.kind {
                todos(ss, &mut self.0);
            }
            visit::walk_stmt(self, s);
        }
    }
    for it in &krate.items {
        let ItemKind::Fn(f) = &it.kind else { continue };
        if f.law_proof == Some(LawProof::Missing) {
            diags.push(Diagnostic::warning(DiagKind::Law, it.span, format!("open claim: law `{}` has no proof", it.name)).note("add a `#[proof] fn` with the same name and parameters, or an inline proof (DESIGN.md §4.5)"));
        }
        let mut spans = Vec::new();
        if let FnBody::Script(ss) = &f.body {
            todos(ss, &mut spans);
        }
        let mut pb = ProofBlocks(vec![]);
        visit::walk_fn(&mut pb, f);
        spans.extend(pb.0);
        for sp in spans {
            diags.push(Diagnostic::warning(DiagKind::Script, sp, "`todo()` leaves a proof goal open"));
        }
    }
}

/// Rewrites script applications of `#[proof]` items (other than a proof's
/// own recursive calls) to the law they prove.
fn redirect_proof_apps(krate: &mut Crate) {
    let proves: HashMap<ItemId, ItemId> = krate.items.iter().filter_map(|i| match &i.kind {
        ItemKind::Fn(f) => f.proves.map(|l| (i.id, l)),
        _ => None,
    }).collect();
    fn fix_expr(e: &mut Expr, me: ItemId, proves: &HashMap<ItemId, ItemId>) {
        if let ExprKind::Call { callee: Callee::Item(id, _), args } = &mut e.kind {
            if *id != me
                && let Some(l) = proves.get(id) {
                    *id = *l;
                }
            for a in args {
                fix_expr(a, me, proves);
            }
        }
    }
    fn fix(ss: &mut [ScriptStmt], me: ItemId, proves: &HashMap<ItemId, ItemId>) {
        for s in ss {
            match &mut s.kind {
                ScriptKind::Apply { app, .. } | ScriptKind::Exact(app) => fix_expr(app, me, proves),
                ScriptKind::Rewrite { eq, .. } => fix_expr(eq, me, proves),
                ScriptKind::Using(ids) => {
                    for id in ids.iter_mut() {
                        if *id != me
                            && let Some(l) = proves.get(id) {
                                *id = *l;
                            }
                    }
                }
                ScriptKind::Assert { steps: Some(st), .. } => fix(st, me, proves),
                ScriptKind::Match { arms, .. } => arms.iter_mut().for_each(|a| fix(&mut a.steps, me, proves)),
                ScriptKind::If { then, els, .. } => {
                    fix(then, me, proves);
                    fix(els, me, proves);
                }
                ScriptKind::Cases { steps, .. } => fix(steps, me, proves),
                ScriptKind::Calc { links, .. } => links.iter_mut().filter_map(|l| l.steps.as_mut()).for_each(|st| fix(st, me, proves)),
                _ => {}
            }
        }
    }
    for it in &mut krate.items {
        let me = it.id;
        if let ItemKind::Fn(f) = &mut it.kind
            && let FnBody::Script(ss) = &mut f.body {
                fix(ss, me, &proves);
            }
    }
}

fn param_name(f: &FnDef, p: &Param) -> String {
    match &p.pat.kind {
        PatKind::Binding { local, .. } => f.local(*local).name.clone(),
        _ => "_".into(),
    }
}

// ----------------------------------------------------------------------
// implements
// ----------------------------------------------------------------------

fn check_implements(krate: &Crate, diags: &mut Diagnostics) {
    for it in &krate.items {
        let ItemKind::Fn(f) = &it.kind else { continue };
        let Some(target) = f.implements else { continue };
        let Some(t) = krate.fn_def(target) else { continue };
        if f.target_features.is_empty() {
            diags.push(Diagnostic::error(DiagKind::Contract, f.sig_span, "`#[implements]` is only allowed on `#[target_feature]` functions").note("variants implement a portable function with hardware features (DESIGN.md §9.3)"));
        }
        if t.kind != FnKind::Exec || krate.item(target).ghost {
            diags.error(DiagKind::Contract, f.sig_span, "`#[implements]` must name an exec function");
        }
        if t.implements.is_some() {
            diags.error(DiagKind::Contract, f.sig_span, "`#[implements]` must name the portable function, not another variant");
        }
        if !t.target_features.is_empty() {
            diags.error(DiagKind::Contract, f.sig_span, "the implemented function must be portable (no `#[target_feature]`)");
        }
        let a: Vec<&Ty> = f.params.iter().map(|p| &p.ty).collect();
        let b: Vec<&Ty> = t.params.iter().map(|p| &p.ty).collect();
        if a != b || f.ret != t.ret || !f.generics.is_empty() || !t.generics.is_empty() {
            diags.push(Diagnostic::error(DiagKind::Contract, f.sig_span, format!("`{}` must have the same signature as `{}`", it.name, krate.item(target).name)).note_at(t.sig_span, "implemented function"));
        }
    }
}
