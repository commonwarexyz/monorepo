//! The global elaboration order (DESIGN.md §7.1): every item after the
//! items it mentions (types, constants, callees, lemma applications); a law
//! after everything its proof mentions. Self-recursion is the only cycle
//! the front end admits. The order is deterministic (depth-first,
//! post-order, in item order).
//!
//! §15 edges (DESIGN.md §15): a `#[refines(s)]` function after its spec
//! `s` and everything its argument map, domain and examples mention; a
//! `#[proof(refines | complete = f)]` item after `f`; a function calling `f`
//! after `f`'s `#[proof(refines = f)]` item (S1: `f::refines` is built
//! there and is a fact at the call); a `#[fuel_sufficient(s)]` lemma after
//! `s`; a type after what its invariants, view (including the target of a
//! structural view) and representation relation mention; an exec function
//! mentioning a struct after that struct's `#[proof(view_inj = T)]` item
//! (S2: the determinacy of its refinement uses `T::view_inj`).

use std::collections::{BTreeSet, HashSet};

use crate::hir::*;
use crate::visit::{self, Visitor};

struct Refs {
    out: BTreeSet<ItemId>,
}

impl Refs {
    fn ty(&mut self, t: &Ty) {
        t.walk(&mut |x| {
            if let Ty::Adt(id, _) = x {
                self.out.insert(*id);
            }
        });
    }
}

impl Visitor for Refs {
    fn expr(&mut self, e: &Expr) {
        self.ty(&e.ty);
        match &e.kind {
            ExprKind::Call { callee: Callee::Item(id, targs), .. } => {
                self.out.insert(*id);
                targs.iter().for_each(|t| self.ty(t));
            }
            ExprKind::Call { callee: Callee::Builtin(_, targs) | Callee::Ghost(_, targs), .. } => targs.iter().for_each(|t| self.ty(t)),
            ExprKind::Const(id) => {
                self.out.insert(*id);
            }
            ExprKind::Adt { ctor: Ctor::Struct(id) | Ctor::Variant(id, _), .. } => {
                self.out.insert(*id);
            }
            ExprKind::Cast(_, t) => self.ty(t),
            _ => {}
        }
        visit::walk_expr(self, e);
    }
    fn pat(&mut self, p: &Pat) {
        self.ty(&p.ty);
        if let PatKind::Ctor { ctor: Ctor::Struct(id) | Ctor::Variant(id, _), .. } = &p.kind {
            self.out.insert(*id);
        }
        visit::walk_pat(self, p);
    }
    fn script(&mut self, s: &ScriptStmt) {
        if let ScriptKind::Unfold(UnfoldTarget::Item(id)) = &s.kind {
            self.out.insert(*id);
        }
        if let ScriptKind::Using(ids) = &s.kind {
            self.out.extend(ids.iter().copied());
        }
        if let ScriptKind::Unfolding(ts) = &s.kind {
            for t in ts {
                if let UnfoldTarget::Item(id) = t {
                    self.out.insert(*id);
                }
            }
        }
        visit::walk_script(self, s);
    }
}

/// The items `id` refers to (including the §15 edges).
pub fn refs(krate: &Crate, id: ItemId) -> BTreeSet<ItemId> {
    refs_with(krate, id, true)
}

/// The items the *statement* of `id` refers to: for a law, lemma or proof
/// item its parameters, `requires`, `ensures`, `decreases` and §15
/// annotations — not its proof (the body or the `#[proof]` item of a law);
/// for any other item [`refs`]. The incremental spec-mutation gate
/// (`crate::mutate::cache`) keys a mutant's verdict on what it reaches this
/// way: proofs are irrelevant to every decided verdict.
pub fn statement_refs(krate: &Crate, id: ItemId) -> BTreeSet<ItemId> {
    match &krate.item(id).kind {
        ItemKind::Fn(f) if matches!(f.kind, FnKind::Law | FnKind::Lemma | FnKind::Proof) => {
            let mut g = f.clone();
            g.body = FnBody::Claim;
            g.law_proof = None;
            let mut r = Refs { out: BTreeSet::new() };
            fn_refs(&mut r, &g);
            fn_spec_refs(&mut r, &g);
            if let Some(o) = g.owner {
                r.out.insert(o);
            }
            r.out.remove(&id);
            r.out
        }
        _ => refs(krate, id),
    }
}

/// The items `id` refers to; the §15 edges only with `spec15`.
fn refs_with(krate: &Crate, id: ItemId, spec15: bool) -> BTreeSet<ItemId> {
    let mut r = Refs { out: BTreeSet::new() };
    let it = krate.item(id);
    match &it.kind {
        ItemKind::Struct(s) => {
            s.fields.iter().for_each(|f| r.ty(&f.ty));
            if spec15 {
                type_spec_refs(&mut r, &it.kind);
            }
        }
        ItemKind::Enum(e) => {
            e.variants.iter().flat_map(|v| &v.fields).for_each(|f| r.ty(&f.ty));
            if spec15 {
                type_spec_refs(&mut r, &it.kind);
            }
        }
        ItemKind::Const(c) => {
            r.ty(&c.ty);
            r.expr(&c.init);
        }
        ItemKind::TypeAlias(a) => r.ty(&a.ty),
        ItemKind::Fn(f) => {
            fn_refs(&mut r, f);
            if spec15 {
                fn_spec_refs(&mut r, f);
            }
            if let Some(LawProof::Item(p)) = f.law_proof
                && let Some(pf) = krate.fn_def(p)
            {
                fn_refs(&mut r, pf);
                r.out.remove(&p);
            }
            if let Some(o) = f.owner {
                r.out.insert(o);
            }
            // a refinement proven by a `#[proof(refines = g)]` item is built
            // when that item is reached: callers of `g` come after it, so
            // `g::refines` is a fact at their calls (DESIGN.md §15.2)
            if spec15 {
                // (not for a recursive call of `id` itself: its own proof item
                // comes after it, so that edge would be a cycle and the item
                // would be reached before `id`)
                let proofs: Vec<ItemId> = r.out.iter().filter(|c| **c != id).filter_map(|c| krate.fn_def(*c).and_then(|g| g.spec.refines_proof)).filter(|p| *p != id).collect();
                r.out.extend(proofs);
                // an exec function over a type whose view is proven injective
                // by a `#[proof(view_inj = T)]` item comes after that item:
                // the determinacy of its refinement uses it (§15.2, S2)
                if f.kind == FnKind::Exec {
                    let vproofs: Vec<ItemId> = r.out.iter().filter(|c| matches!(&krate.item(**c).kind, ItemKind::Struct(s) if s.view.is_some())).filter_map(|c| super::invariant::view_inj_proof_of(krate, *c)).filter(|p| *p != id).collect();
                    r.out.extend(vproofs);
                }
            }
        }
    }
    r.out.remove(&id);
    r.out
}

fn fn_refs(r: &mut Refs, f: &FnDef) {
    for p in &f.params {
        r.ty(&p.ty);
    }
    r.ty(&f.ret);
    for l in &f.locals {
        r.ty(&l.ty);
    }
    visit::walk_fn(r, f);
}

/// The §15 edges of a function.
fn fn_spec_refs(r: &mut Refs, f: &FnDef) {
    visit::walk_fn_spec(r, &f.spec);
    for ex in &f.spec.examples {
        ex.locals.iter().for_each(|l| r.ty(&l.ty));
    }
    if let Some(x) = &f.spec.refines {
        r.out.insert(x.spec);
    }
    if let Some(p) = &f.spec.proof_of {
        r.out.insert(p.target);
    }
    if let Some(FuelSufficient { spec: Some(s), .. }) = &f.spec.fuel_sufficient {
        r.out.insert(*s);
    }
}

/// The §15 edges of a struct or enum.
fn type_spec_refs(r: &mut Refs, kind: &ItemKind) {
    visit::walk_type_spec(r, kind);
    let (inv, view, rep) = match kind {
        ItemKind::Struct(s) => (s.invariant.as_ref(), s.view.as_ref(), s.represents.as_ref()),
        ItemKind::Enum(e) => (None, e.view.as_ref(), None),
        _ => return,
    };
    if let Some(i) = inv {
        i.locals.iter().for_each(|l| r.ty(&l.ty));
    }
    match view {
        Some(View::Struct { target, .. }) => {
            r.out.insert(*target);
        }
        Some(View::Fn { locals, .. }) => locals.iter().for_each(|l| r.ty(&l.ty)),
        None => {}
    }
    if let Some(x) = rep {
        r.ty(&x.abs_ty);
        x.locals.iter().for_each(|l| r.ty(&l.ty));
    }
}

/// Dependency order of all items.
pub fn dependency_order(krate: &Crate) -> Vec<ItemId> {
    let n = krate.items.len();
    let mut state = vec![0u8; n]; // 0 new, 1 active, 2 done
    let mut out = Vec::with_capacity(n);
    fn visit(krate: &Crate, id: ItemId, state: &mut [u8], out: &mut Vec<ItemId>) {
        let i = id.0 as usize;
        if state[i] != 0 {
            return;
        }
        state[i] = 1;
        for r in refs(krate, id) {
            visit(krate, r, state, out);
        }
        state[i] = 2;
        out.push(id);
    }
    // the lemmas of `#[bridges]` modules first (with what they mention):
    // they are rules of `auto` for every proof after them (layered proofs)
    for it in krate.items.iter().filter(|it| krate.in_bridges_module(it.id)) {
        visit(krate, it.id, &mut state, &mut out);
    }
    for it in &krate.items {
        visit(krate, it.id, &mut state, &mut out);
    }
    out
}

/// Exec functions that are hardware code: `#[target_feature]`,
/// `#[implements]`, intrinsic or load/store-helper calls (§9.2, §9.3),
/// transitively over callers (not over §15 edges: an `#[example]` that
/// mentions a hardware function does not make its item hardware code).
pub fn hardware_items(krate: &Crate, _sem: &super::semantics::Semantics) -> HashSet<ItemId> {
    struct Hw(bool);
    impl Visitor for Hw {
        fn expr(&mut self, e: &Expr) {
            if matches!(&e.kind, ExprKind::Call { callee: Callee::Intrinsic(..) | Callee::Helper(_), .. }) || matches!(&e.ty, Ty::Vector(_)) {
                self.0 = true;
            }
            visit::walk_expr(self, e);
        }
    }
    let mut hw: HashSet<ItemId> = HashSet::new();
    for it in &krate.items {
        if let ItemKind::Fn(f) = &it.kind
            && f.kind == FnKind::Exec
        {
            let mut v = Hw(!f.target_features.is_empty() || f.implements.is_some());
            visit::walk_fn(&mut v, f);
            if v.0 {
                hw.insert(it.id);
            }
        }
    }
    // callers of hardware functions are hardware functions
    loop {
        let mut changed = false;
        for it in &krate.items {
            if hw.contains(&it.id) {
                continue;
            }
            if let ItemKind::Fn(f) = &it.kind
                && f.kind == FnKind::Exec
                && refs_with(krate, it.id, false).iter().any(|r| hw.contains(r))
            {
                hw.insert(it.id);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    hw
}
