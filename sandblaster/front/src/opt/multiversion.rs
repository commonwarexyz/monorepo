//! Multiversioning (DESIGN.md §9.3): hardware variants, variant sets,
//! cloned call trees and their dispatch.
//!
//! * A **variant** is an exec function with `#[implements(portable)]` and a
//!   `#[target_feature]` set. It may be dispatched only if (a) its
//!   definition is kernel-checked, (b) its `VariantEquiv` obligation
//!   (`∀x. variant(x) == portable(x)`) is kernel-checked
//!   ([`super::variant`]), and (c) every intrinsic it (transitively) calls
//!   has hardware evidence for the build target
//!   (`sandblaster_targets::evidence::is_validated`, §9.2 fail-closed).
//! * A **variant set** groups the dispatchable variants with one feature
//!   set (on aarch64: `{sha2}` ↦ `compress_sha2`).
//! * The **call tree** of a set is every exec function that transitively
//!   calls a portable function of the set, except methods and generic
//!   functions ([`not_clonable`]: clones and dispatchers are free,
//!   monomorphic functions), which keep calling the portable code and stop
//!   the tree from growing through them. Each is cloned once per set
//!   ([`clone_tree`]): the clone `f__<set>` is `f` with every call of a
//!   tree function `g` redirected to `g__<set>`, every call of a portable
//!   function redirected to its variant, and the set's
//!   `#[target_feature]` attached, so constant padding blocks reach the
//!   intrinsic models when the clone is specialized (§9.5).
//! * Clones are ordinary exec functions: they are elaborated and
//!   kernel-checked like source functions (every obligation re-proven), and
//!   each clone's kernel body is checked **α-equivalent in all relevant
//!   positions** to the original's modulo the renaming
//!   (`Env::alpha_eq_relevant` with the correspondence clone ↔ original,
//!   variant ↔ portable, and their loop helpers / `ensures`). With the
//!   kernel-checked `VariantEquiv` lemmas this is the "same conversion
//!   argument" of §9.3: replacing pointwise-equal functions in every
//!   relevant position preserves the denotation (by well-founded induction
//!   on the definition order and, for recursive clones, on the shared
//!   measure). The optimizer also turns the argument into kernel-checked
//!   lemmas `f__<set>::clone_equiv` (`super::mirror`); a clone without one
//!   is reported (a warning, an error in strict mode).
//! * Dispatch happens once, at the boundary: each exported function of the
//!   tree gets a trusted dispatcher (fixed template, [`dispatcher_text`])
//!   choosing `f__<set>` when the set's features are enabled — statically
//!   (`cfg(target_feature)`) when `CARGO_CFG_TARGET_FEATURE` has them, at
//!   run time (cached detection) otherwise — and the portable
//!   `f__portable` else.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::hir::*;

/// Suffix of portable functions that lost their name to a dispatcher.
pub const PORTABLE_SUFFIX: &str = "portable";

/// A dispatchable set of variants sharing one feature set.
#[derive(Clone, Debug)]
pub struct VariantSet {
    /// Name used in clone names (`sha2` → `f__sha2`).
    pub name: String,
    /// `#[target_feature(enable = ..)]` features (as written on the variants).
    pub features: Vec<String>,
    /// Their implication closure.
    pub feature_set: Vec<String>,
    /// portable function → its variant.
    pub map: HashMap<ItemId, ItemId>,
    /// Functions that seed the call tree without calling a variant (a
    /// feature-only set's bit-count users, plan O8; empty for the sets of
    /// `#[implements]` variants).
    pub hot: std::collections::BTreeSet<ItemId>,
    /// A simulated CPU for this set's dispatch (test hooks only, R21;
    /// uninhabited in a production build).
    pub kat_fault: Option<super::hooks::KatFault>,
    /// Functions never cloned into this set's tree (a feature-only set's
    /// functions whose clone was not admitted, plan O8).
    pub blocked: std::collections::BTreeSet<ItemId>,
}

impl VariantSet {
    /// A set of `#[implements]` variants (no feature-only seeds).
    pub fn of_variants(name: String, features: Vec<String>, feature_set: Vec<String>, map: HashMap<ItemId, ItemId>) -> VariantSet {
        VariantSet { name, features, feature_set, map, hot: Default::default(), kat_fault: None, blocked: Default::default() }
    }

    /// Whether the set includes feature-only features (its clones use
    /// primitives compiled with them, plan O8): its dispatch runs the
    /// scalar known-answer test first.
    pub fn feature_only(&self) -> bool {
        self.feature_set.iter().any(|f| SCALAR_FEATURES.contains(&f.as_str()))
    }
}

/// The x86 feature-only set `v3_scalar` (optimizer design §13.1): only
/// primitives (`count_ones`, `leading_zeros`, `trailing_zeros`, variable
/// shifts) compiled with these features, so no intrinsic model and no
/// hardware evidence is involved; dispatched after the known-answer
/// self-test (§13.2).
pub const SCALAR_FEATURES: &[&str] = &["popcnt", "lzcnt", "bmi1", "bmi2"];

/// The x86 set `v4` (design §13.1). `pext`/`pdep` may appear only in its
/// clones (their cost on the Zen 2/3 parts `v3_scalar` also covers is
/// microcode; the cost model prices `pext` accordingly).
pub const V4_FEATURES: &[&str] = &["avx512f", "avx512bw", "avx512vl", "avx512cd", "avx512dq", "avx512vpopcntdq", "avx512ifma", "avx512vbmi", "avx512vbmi2", "gfni", "vaes", "vpclmulqdq", "sha", "bmi1", "bmi2", "lzcnt", "popcnt"];

/// At most this many variant sets per architecture (design §13.1).
pub const MAX_SETS: usize = 4;

/// Whether a function's body uses a primitive whose code depends on the
/// feature-only features: a bit count, a `for` loop with literal bounds (a
/// bit-sum idiom the aegraph rewrites), or a call of a recursive user
/// function (a loop head whose Σ2 closed form uses bit counts).
pub fn bit_sensitive(krate: &Crate, f: &FnDef) -> bool {
    struct V<'a>(&'a Crate, bool);
    impl crate::visit::Visitor for V<'_> {
        fn expr(&mut self, e: &Expr) {
            match &e.kind {
                ExprKind::Call { callee: Callee::Builtin(crate::builtins::Builtin::Int(m, _), _), .. }
                    if matches!(m, crate::builtins::IntMethod::CountOnes | crate::builtins::IntMethod::LeadingZeros | crate::builtins::IntMethod::TrailingZeros) =>
                {
                    self.1 = true
                }
                // a `for` loop over bits (a shift in its body): a bit-sum
                // idiom the aegraph may rewrite to a bit count
                ExprKind::Loop(l) if matches!(&l.kind, LoopKind::ForRange { .. }) && has_shift(&l.body) => self.1 = true,
                ExprKind::Call { callee: Callee::Item(id, _), .. } if self.0.fn_def(*id).is_some_and(|g| g.decreases.is_some() && callees(g).contains(id)) => self.1 = true,
                _ => {}
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut v = V(krate, false);
    if let FnBody::Exec(b) = &f.body {
        crate::visit::Visitor::expr(&mut v, b);
    }
    v.1
}

/// Whether a block shifts (`<<`, `>>`, `wrapping_shl`/`shr`).
fn has_shift(b: &Block) -> bool {
    struct V(bool);
    impl crate::visit::Visitor for V {
        fn expr(&mut self, e: &Expr) {
            match &e.kind {
                ExprKind::Binary(BinOp::Shl | BinOp::Shr, ..) => self.0 = true,
                ExprKind::Call { callee: Callee::Builtin(crate::builtins::Builtin::Shift { .. }, _), .. } => self.0 = true,
                ExprKind::Call { callee: Callee::Builtin(crate::builtins::Builtin::Int(crate::builtins::IntMethod::WrappingShl | crate::builtins::IntMethod::WrappingShr, _), _), .. } => self.0 = true,
                _ => {}
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut v = V(false);
    crate::visit::Visitor::expr(&mut v, &Expr::new(ExprKind::Block(b.clone()), Ty::unit(), b.span));
    v.0
}

/// The feature-only sets of a crate (plan O8), in dispatch preference
/// order, given its sets of `#[implements]` variants: `v4` (absorbing every
/// variant set whose features it includes), each variant set combined with
/// `v3_scalar`, then `v3_scalar`; x86 only (aarch64 `cssc` is not accepted
/// by rustc 1.98 in `#[target_feature]`: decision D2). Empty when no
/// function is bit-sensitive. The caller keeps at most [`MAX_SETS`].
pub fn feature_only_sets(krate: &Crate, arch: &crate::target::Arch, variant_sets: &[VariantSet]) -> Vec<VariantSet> {
    if arch.name() != "x86_64" {
        return vec![];
    }
    let hot: std::collections::BTreeSet<ItemId> = krate
        .items
        .iter()
        .filter(|it| !it.ghost)
        .filter_map(|it| match &it.kind {
            ItemKind::Fn(f) if f.kind == FnKind::Exec && f.implements.is_none() && f.target_features.is_empty() && not_clonable(f).is_none() && !callees(f).contains(&it.id) && bit_sensitive(krate, f) => Some(it.id),
            _ => None,
        })
        .collect();
    if hot.is_empty() {
        return vec![];
    }
    let scalar: Vec<String> = SCALAR_FEATURES.iter().map(|s| s.to_string()).collect();
    let v4f: Vec<String> = V4_FEATURES.iter().map(|s| s.to_string()).collect();
    let v4_closure = crate::target::feature_closure(arch, &v4f);
    let mut v4map: HashMap<ItemId, ItemId> = HashMap::new();
    for s in variant_sets {
        if s.feature_set.iter().all(|f| v4_closure.contains(f)) {
            v4map.extend(s.map.iter().map(|(a, b)| (*a, *b)));
        }
    }
    let mut out = vec![VariantSet { name: "v4".into(), features: v4f, feature_set: v4_closure, map: v4map, hot: hot.clone(), kat_fault: None, blocked: Default::default() }];
    for s in variant_sets {
        let mut features = s.features.clone();
        features.extend(scalar.iter().cloned());
        out.push(VariantSet { name: format!("{}_v3", s.name), feature_set: crate::target::feature_closure(arch, &features), features, map: s.map.clone(), hot: hot.clone(), kat_fault: None, blocked: Default::default() });
    }
    out.push(VariantSet { name: "v3_scalar".into(), feature_set: crate::target::feature_closure(arch, &scalar), features: scalar, map: HashMap::new(), hot, kat_fault: None, blocked: Default::default() });
    out
}

/// Every call of a user item in a function (exec calls only).
pub fn callees(f: &FnDef) -> BTreeSet<ItemId> {
    struct C(BTreeSet<ItemId>);
    impl crate::visit::Visitor for C {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Call { callee: Callee::Item(id, _), .. } = &e.kind {
                self.0.insert(*id);
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut c = C(BTreeSet::new());
    if let FnBody::Exec(b) = &f.body {
        crate::visit::Visitor::expr(&mut c, b);
    }
    c.0
}

/// Why a function cannot be cloned into a call tree (`None`: it can).
/// Methods and generic functions stay portable (red team R2/R2b): a clone
/// is printed as a free function and a boundary dispatcher is a free,
/// monomorphic function (fixed template), so neither could take a receiver
/// or type parameters.
pub fn not_clonable(f: &FnDef) -> Option<&'static str> {
    if f.owner.is_some() || f.receiver.is_some() {
        Some("a method (clones and dispatchers are free functions); it keeps calling the portable code")
    } else if !f.generics.is_empty() {
        Some("a generic function (dispatchers are monomorphic templates); it keeps calling the portable code")
    } else {
        None
    }
}

/// The call tree of a set: exec functions (not variants) that transitively
/// call a portable function of the set, in item order. Functions that
/// cannot be cloned ([`not_clonable`]) are left out, with the reason, and
/// the tree does not grow through them.
pub fn call_tree_excluding(krate: &Crate, set: &VariantSet) -> (Vec<ItemId>, Vec<(ItemId, &'static str)>) {
    let variants: HashSet<ItemId> = set.map.values().copied().collect();
    let mut tree: HashSet<ItemId> = HashSet::new();
    let mut excluded: Vec<(ItemId, &'static str)> = Vec::new();
    let calls: HashMap<ItemId, BTreeSet<ItemId>> = krate
        .items
        .iter()
        .filter_map(|it| match &it.kind {
            ItemKind::Fn(f) if f.kind == FnKind::Exec && !it.ghost => Some((it.id, callees(f))),
            _ => None,
        })
        .collect();
    loop {
        let mut changed = false;
        for (id, cs) in &calls {
            // (another set's clones, and every `#[target_feature]` function,
            // stay out of a tree: a clone is cloned once, from its original)
            if tree.contains(id) || variants.contains(id) || set.map.contains_key(id) || set.blocked.contains(id) || excluded.iter().any(|(e, _)| e == id) || krate.fn_def(*id).is_some_and(|f| !f.target_features.is_empty()) {
                continue;
            }
            if set.hot.contains(id) || cs.iter().any(|c| set.map.contains_key(c) || tree.contains(c)) {
                match krate.fn_def(*id).and_then(not_clonable) {
                    Some(why) => excluded.push((*id, why)),
                    None => {
                        tree.insert(*id);
                    }
                }
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut v: Vec<ItemId> = tree.into_iter().collect();
    v.sort();
    excluded.sort();
    (v, excluded)
}

/// The call tree of a set (see [`call_tree_excluding`]).
pub fn call_tree(krate: &Crate, set: &VariantSet) -> Vec<ItemId> {
    call_tree_excluding(krate, set).0
}

/// Renames every exec call in an expression (body, contracts and ghost
/// code alike) through `map`.
pub fn rename_calls(e: &mut Expr, map: &dyn Fn(ItemId) -> Option<ItemId>) {
    if let ExprKind::Call { callee: Callee::Item(id, _), .. } = &mut e.kind
        && let Some(n) = map(*id)
    {
        *id = n;
    }
    match &mut e.kind {
        ExprKind::Lit(_) | ExprKind::Local(_) | ExprKind::Const(_) | ExprKind::BuiltinConst(_) | ExprKind::Unreachable => {}
        ExprKind::Call { args, .. } => args.iter_mut().for_each(|a| rename_calls(a, map)),
        ExprKind::Adt { fields, base, .. } => {
            fields.iter_mut().for_each(|(_, x)| rename_calls(x, map));
            if let Some(b) = base {
                rename_calls(b, map);
            }
        }
        ExprKind::Tuple(es) | ExprKind::Array(es) => es.iter_mut().for_each(|x| rename_calls(x, map)),
        ExprKind::Repeat { elem, .. } => rename_calls(elem, map),
        ExprKind::Field { base, .. } => rename_calls(base, map),
        ExprKind::Index { base, index } => {
            rename_calls(base, map);
            rename_calls(index, map);
        }
        ExprKind::SliceRange { base, lo, hi } => {
            rename_calls(base, map);
            if let Some(x) = lo {
                rename_calls(x, map);
            }
            if let Some(x) = hi {
                rename_calls(x, map);
            }
        }
        ExprKind::Unary(_, x) | ExprKind::Cast(x, _) | ExprKind::Ref(x) | ExprKind::Deref(x) | ExprKind::Coerce(_, x) | ExprKind::Try(x) | ExprKind::PropNot(x) => rename_calls(x, map),
        ExprKind::Binary(_, a, b) | ExprKind::PropEq(a, b) | ExprKind::PropNe(a, b) | ExprKind::PropAnd(a, b) | ExprKind::PropOr(a, b) | ExprKind::Implies(a, b) | ExprKind::Iff(a, b) => {
            rename_calls(a, map);
            rename_calls(b, map);
        }
        ExprKind::If { cond, then, els } => {
            rename_calls(cond, map);
            rename_calls(then, map);
            if let Some(x) = els {
                rename_calls(x, map);
            }
        }
        ExprKind::Match { scrut, arms, .. } => {
            rename_calls(scrut, map);
            for a in arms {
                if let Some(g) = &mut a.guard {
                    rename_calls(g, map);
                }
                rename_calls(&mut a.body, map);
            }
        }
        ExprKind::Block(b) => rename_block(b, map),
        ExprKind::Return(x) => {
            if let Some(x) = x {
                rename_calls(x, map);
            }
        }
        ExprKind::Loop(l) => {
            match &mut l.kind {
                LoopKind::ForRange { lo, hi, .. } => {
                    rename_calls(lo, map);
                    rename_calls(hi, map);
                }
                LoopKind::While { cond } => rename_calls(cond, map),
            }
            rename_block(&mut l.body, map);
            l.info.invariants.iter_mut().for_each(|x| rename_calls(x, map));
            if let Some(d) = &mut l.info.decreases {
                rename_calls(d, map);
            }
        }
        ExprKind::Quant { body, .. } | ExprKind::Lambda { body, .. } => rename_calls(body, map),
        ExprKind::Apply { fun, args } => {
            rename_calls(fun, map);
            args.iter_mut().for_each(|a| rename_calls(a, map));
        }
    }
}

fn rename_block(b: &mut Block, map: &dyn Fn(ItemId) -> Option<ItemId>) {
    for s in &mut b.stmts {
        match &mut s.kind {
            StmtKind::Let { init, els, .. } => {
                rename_calls(init, map);
                if let Some(bl) = els {
                    rename_block(bl, map);
                }
            }
            StmtKind::Expr(x) => rename_calls(x, map),
            StmtKind::Assign { place, value } | StmtKind::CompoundAssign { place, value, .. } => {
                rename_calls(value, map);
                for p in &mut place.projs {
                    if let Proj::Index(i) = p {
                        rename_calls(i, map);
                    }
                }
            }
            StmtKind::CopyFromSlice { range, src, .. } => {
                if let Some((a, b)) = range {
                    if let Some(a) = a {
                        rename_calls(a, map);
                    }
                    if let Some(b) = b {
                        rename_calls(b, map);
                    }
                }
                rename_calls(src, map);
            }
            StmtKind::Proof(_) => {}
        }
    }
    if let Some(t) = &mut b.tail {
        rename_calls(t, map);
    }
}

/// The clone of every tree function for `set`, appended to `krate`
/// (in the defining module, after the original). Returns original → clone.
pub fn clone_tree(krate: &mut Crate, set: &VariantSet, tree: &[ItemId]) -> HashMap<ItemId, ItemId> {
    let mut map: HashMap<ItemId, ItemId> = HashMap::new();
    let base = krate.items.len() as u32;
    for (k, id) in tree.iter().enumerate() {
        map.insert(*id, ItemId(base + k as u32));
    }
    let redirect = |id: ItemId| -> Option<ItemId> { map.get(&id).copied().or_else(|| set.map.get(&id).copied()) };
    for (k, id) in tree.iter().enumerate() {
        let orig = krate.item(*id).clone();
        let ItemKind::Fn(mut f) = orig.kind.clone() else { continue };
        if let FnBody::Exec(b) = &mut f.body {
            rename_calls(b, &redirect);
        }
        f.requires.iter_mut().for_each(|r| rename_calls(r, &redirect));
        if let Some(en) = &mut f.ensures {
            rename_calls(&mut en.prop, &redirect);
        }
        if let Some(d) = &mut f.decreases {
            rename_calls(&mut d.measure, &redirect);
        }
        f.target_features = set.features.clone();
        f.feature_set = set.feature_set.clone();
        f.implements = None;
        f.impl_block = None;
        let name = format!("{}__{}", orig.name, set.name);
        let mut path = orig.path.clone();
        if let Some(last) = path.0.last_mut() {
            *last = name.clone();
        }
        let id2 = ItemId(base + k as u32);
        let item = Item { id: id2, name, path, module: orig.module, vis: Vis::Crate, ghost: false, span: orig.span, docs: vec![format!(" Multiversioned clone of `{}` for the variant set `{{{}}}` (DESIGN.md §9.3).", orig.path, set.name)], allow: orig.allow.clone(), cfg: set_cfg(krate, set), kind: ItemKind::Fn(f) };
        krate.items.push(item);
        let m = orig.module;
        krate.modules[m.0 as usize].items.push(id2);
    }
    map
}

/// The `cfg` of a set's clones: the variants' own `cfg` (target arch and
/// endianness); a feature-only set's clones are for its architecture.
fn set_cfg(krate: &Crate, set: &VariantSet) -> Option<String> {
    set.map.values().next().and_then(|v| krate.item(*v).cfg.clone()).or_else(|| set.feature_only().then(|| "all(target_arch = \"x86_64\", target_endian = \"little\")".to_string()))
}
