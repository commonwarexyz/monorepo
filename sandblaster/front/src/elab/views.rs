//! Views and representation relations (DESIGN.md §15.3, stage **S1**).
//!
//! The abstraction `α(from ↦ to)` of a value is type-directed
//! ([`Elab::abstraction`]; the typechecker's [`crate::hir::Coercion::View`]
//! and the refinement statements of `refines.rs` both use it):
//!
//! | from | to | `α x` |
//! | --- | --- | --- |
//! | `T` | `T` | `x` |
//! | `&T` | `α(T)` | `α x` (references are the identity in the model) |
//! | `Nat` | `Int` | `x` |
//! | `uN` | `Nat`, `Int` | `cast_uN_int(x)` |
//! | `&[T]` | `Seq<U>` | `map α (list x)` (`list x` when `T = U`) |
//! | `[T; N]`, `Seq<T>` | `Seq<U>` | `map α (fst x)`, `map α x` |
//! | `[T; N]` | `[T; N]` | `x` (element-wise views of arrays: use `Seq<U>`) |
//! | `Option<A>` | `Option<B>` | `match x { None => None, Some(v) => Some(α v) }` |
//! | `(A₀, …)` | `(B₀, …)` | `(α π₀ x, …)` |
//! | a type with `#[view]` | its view type `V` (and on) | `α(T::view x)` |
//! | a one-field struct with `#[invariant]` (S2) | the field's type (and on) | `α(π₀ x)` |
//! | a `core::arch` vector (`uint8x16_t`) | the array of its lanes `[u8; 16]` (and on) | `x` (the same kernel type, `docs/mir-lift.md` §20.9) |
//! | the array of a vector's lanes | the vector | `x` |
//!
//! A type's `#[view]` is the kernel definition `T::view : Π(A..). T(A..)
//! → V` (`DefKind::Spec`, a spec item: spec-closed, printed and locked):
//! `#[view(|s| e)]` is `λs. e`; the structural `#[view(spec::T)]` maps every
//! field to the same-named field of the spec struct through the field
//! coercion. `#[represents(|s: &S, a: A| P)]` is `S::represents : Π(A..).
//! S → A → Type`.
//!
//! **Injectivity** ([`Elab::view_injective`]): the identity, `uN ↦ Nat |
//! Int`, `Nat ↦ Int`, sequences, options and tuples of injective views and
//! the structural view (every field mapped by an injective view) are
//! injective by construction; a `#[view(|s| e)]` is not known to be
//! (`ViewInjective`, S2), so a refinement through it is reported "up to
//! view(T)" (DESIGN.md §15.2 determinacy).

use std::collections::HashMap;

use sandblaster_kernel::term::{Arm, DefKind, GlobalId, PrimOp, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::{mk, shift};

use super::items::{lam_tele, pi_tele, TBinder};
use super::{internal, unsupported, Elab, FnState, Val, R};
use crate::hir::*;
use crate::span::Span;

/// A type's elaborated `#[view]`.
#[derive(Clone, Debug)]
pub struct ViewInfo {
    /// `T::view`.
    pub global: GlobalId,
    /// The view type (over the type's parameters, `Param(i)`).
    pub target: Ty,
    /// Injective by construction (structural view of injective field
    /// views); `false` for `#[view(|s| e)]` until S2's `ViewInjective`.
    pub injective: bool,
}

/// The per-crate state of the §15 S1 stages (views, refinements,
/// examples, spec closure), kept on [`Elab`].
#[derive(Default)]
pub struct S1State {
    /// The spec-level stages run (the main elaboration; off for `exec_only`
    /// tests).
    pub on: bool,
    pub views: HashMap<ItemId, ViewInfo>,
    /// `S::represents`, by struct.
    pub represents: HashMap<ItemId, GlobalId>,
    pub refinements: Vec<super::refines::RefinesRecord>,
    pub examples: Vec<super::examples::ExampleRecord>,
    pub coverage: Vec<super::examples::CoverageRecord>,
    pub closure: Vec<super::examples::ClosureRecord>,
    /// Exec functions established so far (DESIGN.md §15.1): refined with
    /// an injective view in an earlier item (S3 adds fully specified
    /// sections).
    pub established: std::collections::BTreeSet<GlobalId>,
    /// Spec functions with a checked `#[fuel_sufficient]` lemma.
    pub fuel_ok: std::collections::HashSet<ItemId>,
    /// The closed terms of the accepted examples (a checker applied to a
    /// record for vector files) and whether they count for coverage.
    pub example_terms: Vec<(Tm, bool)>,
    /// Placeholders of definitions that did not verify (an opaque default
    /// body, `Elab::placeholder`), by global, with their names: examples
    /// and refinement goals that reach one are reported as not checked,
    /// never judged against the default.
    pub placeholders: HashMap<GlobalId, String>,
    /// Definitions added to the kernel that use a placeholder (directly or
    /// through another such definition), with the placeholder's name: they
    /// were checked against a stand-in body and are reported blocked
    /// (`Elab::add_definition`).
    pub stand_in_users: HashMap<GlobalId, String>,
    /// The §15 S2 state: invariants, view injectivity
    /// ([`super::invariant::S2State`]).
    pub s2: super::invariant::S2State,
}

impl<'a> Elab<'a> {
    /// `α(from ↦ to) x` (see the module docs); `x` is a term at the current
    /// depth.
    pub fn abstraction(&mut self, from: &Ty, to: &Ty, x: Tm, span: Span) -> R<Tm> {
        self.abstraction_d(from, to, x, span, 0)
    }

    fn abstraction_d(&mut self, from: &Ty, to: &Ty, x: Tm, span: Span, depth: u32) -> R<Tm> {
        if depth > 16 {
            return unsupported(span, "view coercion nested too deeply");
        }
        let f = from.peel_refs().clone();
        let to = to.peel_refs();
        if &f == to {
            return Ok(x);
        }
        match (&f, to) {
            (Ty::Nat, Ty::Int) => Ok(x),
            // a vector is the array of its lanes in the kernel already
            (Ty::Vector(v), _) => {
                let (lane, n) = v.lanes();
                self.abstraction_d(&Ty::Array(Box::new(Ty::Uint(lane)), n), to, x, span, depth + 1)
            }
            (Ty::Array(..), Ty::Vector(_)) => Ok(x),
            (Ty::Uint(w), Ty::Nat | Ty::Int) => Ok(mk::prim(PrimOp::Cast { from: w.width(), to: Width::Int }, vec![x], vec![])),
            (Ty::Slice(e), Ty::Seq(e2)) => {
                let l = mk::fst(mk::snd(x));
                self.seq_map_view(e, e2, l, span, depth)
            }
            (Ty::Array(e, _), Ty::Seq(e2)) => {
                let l = mk::fst(x);
                self.seq_map_view(e, e2, l, span, depth)
            }
            (Ty::Seq(e), Ty::Seq(e2)) => self.seq_map_view(e, e2, x, span, depth),
            (Ty::Array(e, n), Ty::Array(e2, m)) if n == m && e.peel_refs() == &**e2 => Ok(x),
            (Ty::Array(e, n), Ty::Array(e2, _)) => {
                let (a, b) = (self.krate.ty_str(e), self.krate.ty_str(e2));
                unsupported(span, format!("element-wise view of an array (`[{a}; {n}]` ↦ `[{b}; {n}]`) is not supported; view it as `Seq<{b}>`"))
            }
            (Ty::Option(a), Ty::Option(b)) => {
                let (a, b) = ((**a).clone(), (**b).clone());
                let at = self.ty(&a, span)?;
                let bt = self.ty(&b, span)?;
                let opt = self.p.option;
                let none = mk::ctor(opt, 0, vec![bt.clone()], vec![]);
                let saved = self.f.scope.clone();
                let atv = self.eval(&at)?;
                self.push_v("v", Rel::Rel, atv);
                let inner = self.abstraction_d(&a, &b, mk::var(0), span, depth + 1);
                self.f.scope = saved;
                let some = mk::ctor(opt, 1, vec![shift(&bt, 1)], vec![inner?]);
                let motive = shift(&mk::ind(opt, vec![bt]), 1);
                Ok(std::rc::Rc::new(Term::Match { ind: opt, params: vec![at], scrut: x, motive, arms: vec![Arm { names: vec![], body: none }, Arm { names: vec![std::rc::Rc::from("v")], body: some }] }))
            }
            (Ty::Tuple(xs), Ty::Tuple(ys)) if xs.len() == ys.len() && !xs.is_empty() => {
                let (xs, ys) = (xs.clone(), ys.clone());
                let src = Ty::Tuple(xs.clone());
                let (ind, params) = self.ind_of(&src, span)?;
                let mut comps = Vec::new();
                let mut tys = Vec::new();
                for (i, (a, b)) in xs.iter().zip(&ys).enumerate() {
                    let ft = self.ty(a, span)?;
                    let xi = self.proj(ind, params.clone(), x.clone(), i, xs.len(), ft);
                    comps.push(self.abstraction_d(a, b, xi, span, depth + 1)?);
                    tys.push(self.ty(b, span)?);
                }
                self.tuple_val(tys, comps, span)
            }
            (Ty::Adt(id, args), _) => {
                let (id, args) = (*id, args.clone());
                if let Some(v) = self.s1.views.get(&id).cloned().or_else(|| self.view_by_name(id)) {
                    let mut app = mk::global(v.global);
                    for a in &args {
                        app = mk::app(app, self.ty(a, span)?);
                    }
                    let viewed = mk::app(app, x);
                    let vt = v.target.subst(&args);
                    return self.abstraction_d(&vt, to, viewed, span, depth + 1);
                }
                if let ItemKind::Struct(s) = &self.krate.item(id).kind
                    && s.invariant.is_some()
                    && s.fields.len() == 1
                    && s.view.is_none()
                {
                    // an invariant newtype ↦ its field (DESIGN.md §15.3)
                    let fty = s.fields[0].ty.subst(&args);
                    let (ind, params) = self.ind_of(&f, span)?;
                    let ft = self.ty(&fty, span)?;
                    let fld = self.proj(ind, params, x, 0, 1, ft);
                    return self.abstraction_d(&fty, to, fld, span, depth + 1);
                }
                let has_view = match &self.krate.item(id).kind {
                    ItemKind::Struct(s) => s.view.is_some(),
                    ItemKind::Enum(e) => e.view.is_some(),
                    _ => false,
                };
                if has_view {
                    return Err(super::ElabError { span, msg: format!("the view of `{}` is not available", self.krate.item(id).path), kind: super::ErrKind::Blocked });
                }
                internal(span, format!("no view coercion from `{}` to `{}`", self.krate.ty_str(&f), self.krate.ty_str(to)))
            }
            _ => internal(span, format!("no view coercion from `{}` to `{}`", self.krate.ty_str(&f), self.krate.ty_str(to))),
        }
    }

    /// `map (λv. α v) l` (or `l` when the element view is the identity).
    fn seq_map_view(&mut self, e: &Ty, e2: &Ty, l: Tm, span: Span, depth: u32) -> R<Tm> {
        if e.peel_refs() == e2 {
            return Ok(l);
        }
        let et = self.ty(e, span)?;
        let e2t = self.ty(e2, span)?;
        let saved = self.f.scope.clone();
        let etv = self.eval(&et)?;
        self.push_v("v", Rel::Rel, etv);
        let body = self.abstraction_d(e, e2, mk::var(0), span, depth + 1);
        self.f.scope = saved;
        let lam = mk::lam("v", Rel::Rel, et.clone(), body?);
        let map = self.env.lookup_global("ghost::seq_map").ok_or_else(|| super::ElabError { span, msg: "ghost library `ghost::seq_map` is missing".into(), kind: super::ErrKind::Internal })?;
        Ok(mk::apps(mk::global(map), [(Rel::Rel, et), (Rel::Rel, e2t), (Rel::Rel, lam), (Rel::Rel, l)]))
    }

    /// A view elaborated by the main pass, found by name (an elaboration
    /// without the S1 state, in the same environment).
    fn view_by_name(&self, id: ItemId) -> Option<ViewInfo> {
        let it = self.krate.item(id);
        let global = self.env.lookup_global(&format!("{}::view", it.path))?;
        let view = match &it.kind {
            ItemKind::Struct(s) => s.view.as_ref()?,
            ItemKind::Enum(e) => e.view.as_ref()?,
            _ => return None,
        };
        let (target, injective) = match view {
            View::Struct { target, .. } => (Ty::Adt(*target, vec![]), true),
            View::Fn { body, .. } => (body.ty.clone(), false),
        };
        Some(ViewInfo { global, target, injective })
    }

    /// Why `α(from ↦ to)` is not known to be injective (`None`: injective
    /// by construction; see the module docs).
    pub fn view_injective(&self, from: &Ty, to: &Ty) -> Option<String> {
        self.view_injective_d(from, to, 0)
    }

    fn view_injective_d(&self, from: &Ty, to: &Ty, depth: u32) -> Option<String> {
        if depth > 16 {
            return Some("nested too deeply".into());
        }
        let f = from.peel_refs();
        let to = to.peel_refs();
        if f == to {
            return None;
        }
        match (f, to) {
            (Ty::Nat, Ty::Int) | (Ty::Uint(_), Ty::Nat | Ty::Int) => None,
            (Ty::Slice(e) | Ty::Array(e, _) | Ty::Seq(e), Ty::Seq(e2)) | (Ty::Array(e, _), Ty::Array(e2, _)) | (Ty::Option(e), Ty::Option(e2)) => self.view_injective_d(e, e2, depth + 1),
            (Ty::Tuple(xs), Ty::Tuple(ys)) => xs.iter().zip(ys).find_map(|(a, b)| self.view_injective_d(a, b, depth + 1)),
            (Ty::Adt(id, args), _) => match self.s1.views.get(id) {
                Some(v) if v.injective => self.view_injective_d(&v.target.subst(args), to, depth + 1),
                Some(_) => Some(format!("view({})", self.krate.item(*id).name)),
                None => match &self.krate.item(*id).kind {
                    ItemKind::Struct(s) if s.invariant.is_some() && s.fields.len() == 1 => self.view_injective_d(&s.fields[0].ty.subst(args), to, depth + 1),
                    _ => Some(format!("view({})", self.krate.item(*id).name)),
                },
            },
            _ => Some(format!("{} ↦ {}", self.krate.ty_str(f), self.krate.ty_str(to))),
        }
    }

    /// Like [`Elab::view_injective`], but a lossy view of an `Abstract`
    /// type (DESIGN.md §15.3) is accepted: the result coercion `from ↦ to`
    /// *determines* (observational equality through the view, §15.5) —
    /// `None` — or the reason it does not.
    pub fn view_determines(&self, from: &Ty, to: &Ty) -> Option<String> {
        self.view_determines_d(from, to, 0)
    }

    fn view_determines_d(&self, from: &Ty, to: &Ty, depth: u32) -> Option<String> {
        if depth > 16 {
            return Some("nested too deeply".into());
        }
        let f = from.peel_refs();
        let to = to.peel_refs();
        if f == to {
            return None;
        }
        match (f, to) {
            (Ty::Slice(e) | Ty::Array(e, _) | Ty::Seq(e), Ty::Seq(e2)) | (Ty::Array(e, _), Ty::Array(e2, _)) | (Ty::Option(e), Ty::Option(e2)) => self.view_determines_d(e, e2, depth + 1),
            (Ty::Tuple(xs), Ty::Tuple(ys)) => xs.iter().zip(ys).find_map(|(a, b)| self.view_determines_d(a, b, depth + 1)),
            (Ty::Adt(id, args), _) if self.view_injective_d(f, to, depth).is_some() => match self.s1.views.get(id) {
                Some(v) if crate::validate::abstract_reasons(self.krate, *id, false).is_empty() => self.view_determines_d(&v.target.subst(args), to, depth + 1),
                _ => self.view_injective_d(f, to, depth),
            },
            _ => self.view_injective_d(f, to, depth),
        }
    }

    /// The user types with a `#[view]` on the path of the result coercion
    /// `from ↦ to` (see [`Elab::view_determines`]), for the determinacy
    /// reason of a refinement.
    pub fn view_path_types(&self, from: &Ty, to: &Ty) -> Vec<ItemId> {
        let mut out = Vec::new();
        self.view_path_types_d(from, to, 0, &mut out);
        out
    }

    fn view_path_types_d(&self, from: &Ty, to: &Ty, depth: u32, out: &mut Vec<ItemId>) {
        let (f, to) = (from.peel_refs(), to.peel_refs());
        if depth > 16 || f == to {
            return;
        }
        match (f, to) {
            (Ty::Slice(e) | Ty::Array(e, _) | Ty::Seq(e), Ty::Seq(e2)) | (Ty::Array(e, _), Ty::Array(e2, _)) | (Ty::Option(e), Ty::Option(e2)) => self.view_path_types_d(e, e2, depth + 1, out),
            (Ty::Tuple(xs), Ty::Tuple(ys)) => xs.iter().zip(ys).for_each(|(a, b)| self.view_path_types_d(a, b, depth + 1, out)),
            (Ty::Adt(id, args), _) => {
                if let Some(v) = self.s1.views.get(id) {
                    out.push(*id);
                    self.view_path_types_d(&v.target.subst(args), to, depth + 1, out);
                }
            }
            _ => {}
        }
    }

    /// Why a result coercion `from ↦ to` determines its function (§15.2):
    /// `Ok(reason)` — identity, an injective view (naming the `view_inj`
    /// lemmas it uses) or a lossy view of an `Abstract` type (determines
    /// but does not establish) — or `Err(the type whose view is lossy)`.
    pub fn view_determinacy(&self, from: &Ty, to: &Ty) -> Result<String, String> {
        let name = |id: &ItemId| self.krate.item(*id).name.clone();
        let path = self.view_path_types(from, to);
        if self.view_injective(from, to).is_none() {
            if from.peel_refs() == to.peel_refs() {
                return Ok("identity result view".into());
            }
            let proven: Vec<String> = path.iter().filter(|id| matches!(self.s1.s2.view_inj.get(id), Some(Ok(_)))).map(|id| format!("`{}::view_inj`", self.krate.item(*id).path)).collect();
            return Ok(if proven.is_empty() { "injective result view".into() } else { format!("injective result view, by {}", proven.join(", ")) });
        }
        match self.view_determines(from, to) {
            None => {
                let lossy: Vec<String> = path.iter().filter(|id| self.s1.views.get(id).is_some_and(|v| !v.injective)).map(|id| format!("`Abstract({})`", name(id))).collect();
                Ok(format!("{}: a lossy result view, so determined up to the view only; not established", lossy.join(", ")))
            }
            Some(v) => Err(v),
        }
    }

    /// The view type of a type (`None` without a `#[view]`).
    pub fn view_target_ty(&self, t: &Ty) -> Option<Ty> {
        let Ty::Adt(id, args) = t.peel_refs() else { return None };
        self.s1.views.get(id).map(|v| v.target.subst(args))
    }

    /// Elaborates `T::view` for the `#[view]` of type `id` (see the module
    /// docs).
    pub fn view_def(&mut self, id: ItemId, v: &'a View) -> R<()> {
        let krate = self.krate;
        let it = krate.item(id);
        let span = v.span();
        let name = format!("{}::view", it.path);
        let generics: Vec<TyParam> = match &it.kind {
            ItemKind::Struct(s) => s.generics.clone(),
            ItemKind::Enum(e) => e.generics.clone(),
            _ => return internal(span, "a view on a non-type"),
        };
        let self_ty = Ty::Adt(id, generics.iter().enumerate().map(|(i, g)| Ty::Param(i as u32, g.name.clone())).collect());
        let locals: &'a [LocalDecl] = match v {
            View::Fn { locals, .. } => locals,
            View::Struct { .. } => &[],
        };
        self.f = FnState::new(name.clone(), Some(id), locals, span);
        let mut binders = Vec::new();
        for g in &generics {
            self.push(&g.name, Rel::Rel, &mk::ty(), None)?;
            binders.push(TBinder { name: g.name.clone(), rel: Rel::Rel, ty: mk::ty() });
        }
        self.f.ngen = generics.len() as u32;
        let st = self.ty(&self_ty, span)?;
        let lvl = self.push("s", Rel::Rel, &st, None)?;
        binders.push(TBinder { name: "s".into(), rel: Rel::Rel, ty: st });
        let (target, body, injective) = match v {
            View::Fn { binder, body, .. } => {
                self.f.scope.locals.insert(*binder, lvl);
                self.f.answer = body.ty.clone();
                self.f.ret = body.ty.clone();
                // the viewed value's invariant facts (§15.3)
                let sv = Val::new(self.f.scope.var(lvl), self.depth());
                let t = self.with_inv_facts(&sv, &self_ty, span, &mut |s| s.expr(body, &mut |s, v| Ok(v.at(s.depth()))))?;
                (body.ty.clone(), t, false)
            }
            View::Struct { target, .. } => {
                let ItemKind::Struct(src) = &it.kind else { return internal(span, "structural view on an enum") };
                let ItemKind::Struct(tgt) = &krate.item(*target).kind else { return internal(span, "structural view onto a non-struct") };
                let tind = self.adt(*target, span)?;
                let (sind, sparams) = self.ind_of(&self_ty, span)?;
                let s = self.f.scope.var(lvl);
                let mut fields = Vec::new();
                let mut inj = true;
                for tf in &tgt.fields {
                    let j = src.fields.iter().position(|sf| sf.name == tf.name).ok_or_else(|| super::ElabError { span, msg: "structural view: field mismatch".into(), kind: super::ErrKind::Internal })?;
                    let sft = src.fields[j].ty.clone();
                    let ft = self.ty(&sft, span)?;
                    let pj = self.proj(sind, sparams.clone(), s.clone(), j, src.fields.len(), ft);
                    if self.view_injective(&sft, &tf.ty).is_some() {
                        inj = false;
                    }
                    fields.push(self.abstraction(&sft, &tf.ty, pj, span)?);
                }
                // the spec struct's `Irr` fields (its invariant, the bounds
                // of its `Nat` fields: §15.3) are obligations of the view
                let t = self.ctor_with_invariants(tind, 0, vec![], fields, Some(*target), span)?;
                (Ty::Adt(*target, vec![]), t, inj)
            }
        };
        let rty = self.ty(&target, span)?;
        let fty = pi_tele(&binders, rty);
        let lam = lam_tele(&binders, body);
        let arity = binders.len() as u32;
        let failed = self.f.failed;
        let g = self.add_definition(&name, DefKind::Spec, Some(id), fty, lam, Recursion::None, arity, false, failed, span)?;
        self.s1.views.insert(id, ViewInfo { global: g, target, injective });
        // a view is a spec item (DESIGN.md §15.1)
        self.spec_closure_check(id, "the view of", &[mk::global(g)], &[], true, span);
        Ok(())
    }

    /// Elaborates `S::represents` for the `#[represents]` of struct `id`.
    pub fn represents_def(&mut self, id: ItemId, r: &'a Represents) -> R<()> {
        let krate = self.krate;
        let it = krate.item(id);
        let span = r.span;
        let name = format!("{}::represents", it.path);
        let ItemKind::Struct(sd) = &it.kind else { return internal(span, "represents on a non-struct") };
        self.f = FnState::new(name.clone(), Some(id), &r.locals, span);
        let mut binders = Vec::new();
        for g in &sd.generics {
            self.push(&g.name, Rel::Rel, &mk::ty(), None)?;
            binders.push(TBinder { name: g.name.clone(), rel: Rel::Rel, ty: mk::ty() });
        }
        self.f.ngen = sd.generics.len() as u32;
        let self_ty = Ty::Adt(id, sd.generics.iter().enumerate().map(|(i, g)| Ty::Param(i as u32, g.name.clone())).collect());
        let st = self.ty(&self_ty, span)?;
        let l1 = self.push("s", Rel::Rel, &st, None)?;
        self.f.scope.locals.insert(r.repr, l1);
        binders.push(TBinder { name: "s".into(), rel: Rel::Rel, ty: st });
        let at = self.ty(&r.abs_ty, span)?;
        let l2 = self.push("a", Rel::Rel, &at, None)?;
        self.f.scope.locals.insert(r.abs, l2);
        binders.push(TBinder { name: "a".into(), rel: Rel::Rel, ty: at });
        self.f.answer = Ty::Prop;
        self.f.ret = Ty::Prop;
        let body = self.prop(&r.prop)?;
        let fty = pi_tele(&binders, mk::ty());
        let lam = lam_tele(&binders, body);
        let arity = binders.len() as u32;
        let failed = self.f.failed;
        let g = self.add_definition(&name, DefKind::Spec, Some(id), fty, lam, Recursion::None, arity, false, failed, span)?;
        self.s1.represents.insert(id, g);
        // a representation relation is a spec item (DESIGN.md §15.1)
        self.spec_closure_check(id, "the representation relation of", &[mk::global(g)], &[], true, span);
        Ok(())
    }
}
