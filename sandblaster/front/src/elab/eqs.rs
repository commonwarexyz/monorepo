//! Structural equality (DESIGN.md §3.3, §7.7).
//!
//! * `==` on `bool`/integers is the primitive (`bool::eq`, `eq_w`);
//! * arrays: `array::eq T N eqT a b`; slices: `seq::eq T eqT (list a)
//!   (list b)` (arrays compared with slices are unsized first); tuples: the
//!   left-to-right `bool::and` of the components; `Option`: by cases;
//! * user types deriving `PartialEq`: the derived global `T::eq`,
//!   `Π(A : Type).. Π(eq_A : A → A → Bool).. Π(a b : T<A..>). Bool` — a
//!   struct compares its fields left to right with `bool::and`, an enum
//!   compares variants (different variants are unequal) and then fields.
//!   Equality functions of type parameters are passed explicitly (rustc's
//!   `impl<A: PartialEq> PartialEq for T<A>`).
//!
//! For non-generic types whose fields are integers, `bool`, integer arrays
//! or derived types with lemmas, `T::eq_sound : Π(a b)(.h : eq a b = true).
//! a = b` and `T::eq_complete : Π(a b)(.h : a = b). eq a b = true` are
//! proven (SEMANTICS.md §11) and recorded in [`EqGlobals`] for automation
//! (§7.7; `auto` picks them up by name). Types without field lemmas simply
//! get no lemmas.

use std::rc::Rc;

use sandblaster_kernel::term::{Arm, DefKind, GlobalId, PrimOp, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;

use super::items::{lam_tele, pi_tele, TBinder};
use super::{internal, Elab, FnState, ItemGlobal, R};
use crate::hir::*;
use crate::span::Span;

/// The derived equality of a user type and its lemmas.
#[derive(Clone, Debug)]
pub struct EqGlobals {
    pub eq: GlobalId,
    pub sound: Option<GlobalId>,
    pub complete: Option<GlobalId>,
}

impl<'a> Elab<'a> {
    /// `a == b` at a structured type.
    pub fn struct_eq(&mut self, lt: &Ty, rt: &Ty, a: Tm, b: Tm, span: Span) -> R<Tm> {
        match (lt.peel_refs(), rt.peel_refs()) {
            (Ty::Array(e, n), Ty::Slice(_)) => {
                let (e, n) = ((**e).clone(), *n);
                let sa = self.as_slice(&e, n, a, span)?;
                self.eq_at(&Ty::Slice(Box::new(e)), sa, b, &[], span)
            }
            (Ty::Slice(_), Ty::Array(e, n)) => {
                let (e, n) = ((**e).clone(), *n);
                let sb = self.as_slice(&e, n, b, span)?;
                self.eq_at(&Ty::Slice(Box::new(e)), a, sb, &[], span)
            }
            (l, _) => {
                let l = l.clone();
                self.eq_at(&l, a, b, &[], span)
            }
        }
    }

    fn and(&self, x: Tm, y: Tm) -> Tm {
        mk::apps(mk::global(self.p.g("bool::and")), [(Rel::Rel, x), (Rel::Rel, y)])
    }

    /// Boolean equality of `x`, `y : t`; `param_eqs[i]` is the level of the
    /// equality function of type parameter `i`.
    pub fn eq_at(&mut self, t: &Ty, x: Tm, y: Tm, param_eqs: &[u32], span: Span) -> R<Tm> {
        Ok(match t.peel_refs() {
            Ty::Uint(w) => mk::prim(PrimOp::Eq(w.width()), vec![x, y], vec![]),
            Ty::Int | Ty::Nat => mk::prim(PrimOp::Eq(Width::Int), vec![x, y], vec![]),
            Ty::Bool => mk::apps(mk::global(self.p.g("bool::eq")), [(Rel::Rel, x), (Rel::Rel, y)]),
            Ty::Seq(e) => {
                let e = (**e).clone();
                let et = self.ty(&e, span)?;
                let f = self.eq_fn(&e, param_eqs, span)?;
                mk::apps(mk::global(self.p.g("seq::eq")), [(Rel::Rel, et), (Rel::Rel, f), (Rel::Rel, x), (Rel::Rel, y)])
            }
            Ty::Tuple(ts) if ts.is_empty() => self.bool_lit(true),
            Ty::Tuple(ts) => {
                let tt = Ty::Tuple(ts.clone());
                let (ind, params) = self.ind_of(&tt, span)?;
                let mut acc: Option<Tm> = None;
                for (i, ti) in ts.iter().enumerate().rev() {
                    let ft = self.ty(ti, span)?;
                    let xi = self.proj(ind, params.clone(), x.clone(), i, ts.len(), ft.clone());
                    let yi = self.proj(ind, params.clone(), y.clone(), i, ts.len(), ft);
                    let e = self.eq_at(ti, xi, yi, param_eqs, span)?;
                    acc = Some(match acc {
                        None => e,
                        Some(rest) => self.and(e, rest),
                    });
                }
                acc.unwrap()
            }
            Ty::Array(e, n) => {
                let (e, n) = ((**e).clone(), *n);
                let et = self.ty(&e, span)?;
                let f = self.eq_fn(&e, param_eqs, span)?;
                mk::apps(mk::global(self.p.g("array::eq")), [(Rel::Rel, et), (Rel::Rel, mk::lit(Width::Usize, n)), (Rel::Rel, f), (Rel::Rel, x), (Rel::Rel, y)])
            }
            Ty::Slice(e) => {
                let e = (**e).clone();
                let et = self.ty(&e, span)?;
                let f = self.eq_fn(&e, param_eqs, span)?;
                mk::apps(mk::global(self.p.g("seq::eq")), [(Rel::Rel, et), (Rel::Rel, f), (Rel::Rel, mk::fst(mk::snd(x))), (Rel::Rel, mk::fst(mk::snd(y)))])
            }
            Ty::Option(e) => {
                // match x { None => match y { None => true, Some => false },
                //           Some(u) => match y { None => false, Some(v) => eq(u, v) } }
                let e = (**e).clone();
                let et = self.ty(&e, span)?;
                let bool_t = mk::bool_ty(self.p.bool_);
                let opt = self.p.option;
                let d = self.depth();
                let inner_none = Rc::new(Term::Match {
                    ind: opt,
                    params: vec![et.clone()],
                    scrut: y.clone(),
                    motive: bool_t.clone(),
                    arms: vec![Arm { names: vec![], body: self.bool_lit(true) }, Arm { names: vec![Rc::from("v")], body: self.bool_lit(false) }],
                });
                // Some arm: u bound (depth + 1)
                let saved = self.f.scope.clone();
                let etv = self.eval(&et)?;
                self.push_v("u", Rel::Rel, etv.clone());
                let y1 = sandblaster_kernel::util::shift(&y, 1);
                let et1 = sandblaster_kernel::util::shift(&et, 1);
                self.push_v("v", Rel::Rel, etv);
                let eq_uv = self.eq_at(&e, mk::var(1), mk::var(0), param_eqs, span);
                self.f.scope = saved;
                let eq_uv = eq_uv?;
                let inner_some = Rc::new(Term::Match {
                    ind: opt,
                    params: vec![et1],
                    scrut: y1,
                    motive: sandblaster_kernel::util::shift(&bool_t, 1),
                    arms: vec![Arm { names: vec![], body: self.bool_lit(false) }, Arm { names: vec![Rc::from("v")], body: eq_uv }],
                });
                let _ = d;
                Rc::new(Term::Match { ind: opt, params: vec![et], scrut: x, motive: bool_t, arms: vec![Arm { names: vec![], body: inner_none }, Arm { names: vec![Rc::from("u")], body: inner_some }] })
            }
            Ty::Adt(id, args) => {
                let (id, args) = (*id, args.clone());
                let g = match self.eq_fns.get(&id) {
                    Some(e) => e.eq,
                    None => return super::unsupported(span, format!("`{}` has no derived `PartialEq` in the kernel", self.krate.item(id).path)),
                };
                let mut all: Vec<(Rel, Tm)> = Vec::new();
                for a in &args {
                    all.push((Rel::Rel, self.ty(a, span)?));
                }
                for a in &args {
                    all.push((Rel::Rel, self.eq_fn(a, param_eqs, span)?));
                }
                all.push((Rel::Rel, x));
                all.push((Rel::Rel, y));
                mk::apps(mk::global(g), all)
            }
            Ty::Param(i, _) => match param_eqs.get(*i as usize) {
                Some(l) => mk::apps(self.f.scope.var(*l), [(Rel::Rel, x), (Rel::Rel, y)]),
                None => return internal(span, "equality on a type parameter without an equality function"),
            },
            other => return internal(span, format!("no structural equality at `{}`", self.krate.ty_str(other))),
        })
    }

    /// `λ(u v : t). eq_at(t, u, v)`.
    fn eq_fn(&mut self, t: &Ty, param_eqs: &[u32], span: Span) -> R<Tm> {
        if let Ty::Param(i, _) = t.peel_refs()
            && let Some(l) = param_eqs.get(*i as usize)
        {
            return Ok(self.f.scope.var(*l));
        }
        let tt = self.ty(t, span)?;
        let saved = self.f.scope.clone();
        let tv = self.eval(&tt)?;
        self.push_v("u", Rel::Rel, tv.clone());
        self.push_v("v", Rel::Rel, tv);
        let body = self.eq_at(t, mk::var(1), mk::var(0), param_eqs, span);
        self.f.scope = saved;
        let body = body?;
        Ok(mk::lam("u", Rel::Rel, tt.clone(), mk::lam("v", Rel::Rel, sandblaster_kernel::util::shift(&tt, 1), body)))
    }

    /// Defines `T::eq` for a user type deriving `PartialEq` (§7.7).
    pub fn derive_eq(&mut self, id: ItemId) -> R<()> {
        let krate = self.krate;
        let it = krate.item(id);
        let span = it.span;
        let name = format!("{}::eq", it.path);
        let (generics, is_enum) = match &it.kind {
            ItemKind::Struct(s) => (s.generics.clone(), false),
            ItemKind::Enum(e) => (e.generics.clone(), true),
            _ => return internal(span, "not a type"),
        };
        self.f = FnState::new(name.clone(), Some(id), &[], span);
        let ind = self.adt(id, span)?;
        let mut binders = Vec::new();
        for g in &generics {
            self.push(&g.name, Rel::Rel, &mk::ty(), None)?;
            binders.push(TBinder { name: g.name.clone(), rel: Rel::Rel, ty: mk::ty() });
        }
        let n = generics.len() as u32;
        self.f.ngen = n;
        let bool_t = mk::bool_ty(self.p.bool_);
        let mut param_eqs = Vec::new();
        for (i, g) in generics.iter().enumerate() {
            let d = self.depth();
            let a = mk::var(d - 1 - i as u32);
            let fty = mk::pi("_", Rel::Rel, a.clone(), mk::pi("_", Rel::Rel, sandblaster_kernel::util::shift(&a, 1), sandblaster_kernel::util::shift(&bool_t, 2)));
            let nm = format!("eq_{}", g.name);
            let l = self.push(&nm, Rel::Rel, &fty, None)?;
            binders.push(TBinder { name: nm, rel: Rel::Rel, ty: fty });
            param_eqs.push(l);
        }
        let self_ty = Ty::Adt(id, generics.iter().enumerate().map(|(i, g)| Ty::Param(i as u32, g.name.clone())).collect());
        let st = self.ty(&self_ty, span)?;
        let la = self.push("a", Rel::Rel, &st, None)?;
        binders.push(TBinder { name: "a".into(), rel: Rel::Rel, ty: st.clone() });
        let st2 = self.ty(&self_ty, span)?;
        let lb = self.push("b", Rel::Rel, &st2, None)?;
        binders.push(TBinder { name: "b".into(), rel: Rel::Rel, ty: st2 });
        let arity = self.depth();
        let body = if !is_enum {
            let ftys = self.ctor_field_tys(&self_ty, 0, span)?;
            let params: Vec<Tm> = (0..n).map(|i| self.f.scope.var(i)).collect();
            let mut acc: Option<Tm> = None;
            for (k, ft) in ftys.iter().enumerate().rev() {
                let ftm = self.ty(ft, span)?;
                let xa = self.proj(ind, params.clone(), self.f.scope.var(la), k, ftys.len(), ftm.clone());
                let xb = self.proj(ind, params.clone(), self.f.scope.var(lb), k, ftys.len(), ftm);
                let e = self.eq_at(ft, xa, xb, &param_eqs, span)?;
                acc = Some(match acc {
                    None => e,
                    Some(r) => self.and(e, r),
                });
            }
            acc.unwrap_or_else(|| self.bool_lit(true))
        } else {
            self.enum_eq_body(&self_ty, ind, n, la, lb, &param_eqs, span)?
        };
        let ty = pi_tele(&binders, bool_t);
        let lam = lam_tele(&binders, body);
        let failed = self.f.failed;
        let g = self.add_definition(&name, DefKind::Exec, Some(id), ty, lam, Recursion::None, arity, false, failed, span)?;
        self.eq_fns.insert(id, EqGlobals { eq: g, sound: None, complete: None });
        let _ = ItemGlobal::Def(g);
        // soundness and completeness (non-generic types whose fields have
        // equality lemmas); a type without them just has no lemmas
        if generics.is_empty() && !failed {
            let sound = self.derive_eq_sound(id, ind, g, &self_ty, span).ok().flatten();
            let complete = self.derive_eq_complete(id, ind, g, &self_ty, span).ok().flatten();
            if let Some(e) = self.eq_fns.get_mut(&id) {
                e.sound = sound;
                e.complete = complete;
            }
        }
        Ok(())
    }

    /// The equality lemma of a field type: its head applied to the
    /// arguments before `x y .h` (`sound`: `eq x y = true → x = y`;
    /// otherwise `x = y → eq x y = true`).
    fn field_eq_lemma(&self, ft: &Ty, sound: bool) -> Option<Tm> {
        let suffix = if sound { "eq_sound" } else { "eq_complete" };
        match ft.peel_refs() {
            Ty::Uint(w) => Some(mk::global(self.env.lookup_global(&format!("{}::{suffix}", w.name()))?)),
            Ty::Bool => Some(mk::global(self.env.lookup_global(&format!("bool::{suffix}"))?)),
            Ty::Array(e, n) => match e.peel_refs() {
                Ty::Uint(w) => Some(mk::app(mk::global(self.env.lookup_global(&format!("array::{suffix}_{}", w.name()))?), mk::lit(Width::Usize, *n))),
                _ => None,
            },
            Ty::Adt(id, args) if args.is_empty() => {
                let e = self.eq_fns.get(id)?;
                Some(mk::global(if sound { e.sound? } else { e.complete? }))
            }
            _ => None,
        }
    }

    /// `S::eq_sound : Π(a b : S)(.h : Eq(Bool, S::eq a b, true)). Eq(S, a,
    /// b)`: a double match on `a` and `b`; different constructors make `h`
    /// `false = true`; equal ones split `h` into the field equalities
    /// (`bool::and_left/right`), turn each into a field equation with the
    /// field's lemma and rebuild the constructor by transports.
    fn derive_eq_sound(&mut self, id: ItemId, ind: sandblaster_kernel::term::IndId, eqg: GlobalId, self_ty: &Ty, span: Span) -> R<Option<GlobalId>> {
        let krate = self.krate;
        let name = format!("{}::eq_sound", krate.item(id).path);
        let nctors = self.ctor_count(self_ty, span)?;
        let mut field_tys = Vec::new();
        for k in 0..nctors {
            let ftys = self.ctor_field_tys(self_ty, k as u32, span)?;
            for ft in &ftys {
                if self.field_eq_lemma(ft, true).is_none() {
                    return Ok(None);
                }
            }
            field_tys.push(ftys);
        }
        self.f = FnState::new(name.clone(), Some(id), &[], span);
        self.f.mode = super::Mode::Proof;
        let st = self.ty(self_ty, span)?;
        let bool_t = mk::bool_ty(self.p.bool_);
        let tru = self.bool_lit(true);
        let eq_app = |a: Tm, b: Tm| mk::apps(mk::global(eqg), [(Rel::Rel, a), (Rel::Rel, b)]);
        let la = self.push("a", Rel::Rel, &st, None)?;
        let lb = self.push("b", Rel::Rel, &st, None)?;
        let hty = mk::eq(bool_t.clone(), eq_app(self.f.scope.var(la), self.f.scope.var(lb)), tru.clone());
        let lh = self.push("h", Rel::Irr, &hty, None)?;
        let binders = vec![
            TBinder { name: "a".into(), rel: Rel::Rel, ty: st.clone() },
            TBinder { name: "b".into(), rel: Rel::Rel, ty: st.clone() },
            TBinder { name: "h".into(), rel: Rel::Irr, ty: hty },
        ];
        let target = mk::eq(st.clone(), self.f.scope.var(la), self.f.scope.var(lb));
        let decl = self.env.inductive_decl(ind).ok_or_else(|| super::ElabError { span, msg: "unknown inductive".into(), kind: super::ErrKind::Internal })?;
        // outer match on `a`: motive `a'. Π(.h : eq a' b = true). a' = b`
        let mut outer_arms = Vec::new();
        for ka in 0..nctors {
            let saved = self.f.scope.clone();
            let mut xs = Vec::new();
            for ft in &field_tys[ka] {
                let t = self.ty(ft, span)?;
                xs.push(self.push("x", Rel::Rel, &t, None)?);
            }
            // the invariant's `Irr` fields (§15.3): matched, never compared
            let pxs = self.push_irr_fields(ind, ka, &xs, "p")?;
            let ca = mk::ctor(ind, ka as u32, vec![], xs.iter().chain(&pxs).map(|l| self.f.scope.var(*l)).collect());
            let h1ty = mk::eq(bool_t.clone(), eq_app(ca.clone(), self.f.scope.var(lb)), tru.clone());
            let _lh1 = self.push("h", Rel::Irr, &h1ty, None)?;
            let mut inner_arms = Vec::new();
            for kb in 0..nctors {
                let saved2 = self.f.scope.clone();
                let mut ys = Vec::new();
                for ft in &field_tys[kb] {
                    let t = self.ty(ft, span)?;
                    ys.push(self.push("y", Rel::Rel, &t, None)?);
                }
                let pys = self.push_irr_fields(ind, kb, &ys, "q")?;
                let ca2 = mk::ctor(ind, ka as u32, vec![], xs.iter().chain(&pxs).map(|l| self.f.scope.var(*l)).collect());
                let cb = mk::ctor(ind, kb as u32, vec![], ys.iter().chain(&pys).map(|l| self.f.scope.var(*l)).collect());
                let h2ty = mk::eq(bool_t.clone(), eq_app(ca2.clone(), cb.clone()), tru.clone());
                let lh2 = self.push("h", Rel::Irr, &h2ty, None)?;
                // the constructor terms again, after `h` was pushed
                let ca2 = mk::ctor(ind, ka as u32, vec![], xs.iter().chain(&pxs).map(|l| self.f.scope.var(*l)).collect());
                let cb = mk::ctor(ind, kb as u32, vec![], ys.iter().chain(&pys).map(|l| self.f.scope.var(*l)).collect());
                let goal = mk::eq(st.clone(), ca2.clone(), cb.clone());
                let body = if ka != kb {
                    // `h : false = true`
                    let p = self.prove(crate::prover::ObligationKind::WellFormed, span, &goal, true)?;
                    mk::lam("h", Rel::Irr, h2ty, p)
                } else {
                    let fts = field_tys[ka].clone();
                    let n = fts.len();
                    // the conjuncts e_k = eq_k(x_k, y_k) and the rests
                    let mut es = Vec::new();
                    for (k, ft) in fts.iter().enumerate() {
                        let e = self.eq_at(ft, self.f.scope.var(xs[k]), self.f.scope.var(ys[k]), &[], span)?;
                        es.push(e);
                    }
                    let conj = |from: usize, me: &Self| -> Tm {
                        let mut acc: Option<Tm> = None;
                        for e in es[from..].iter().rev() {
                            acc = Some(match acc {
                                None => e.clone(),
                                Some(r) => me.and(e.clone(), r),
                            });
                        }
                        acc.unwrap_or_else(|| me.bool_lit(true))
                    };
                    // lemmas of `lemmas/bool.core` (loaded with the automation's lemmas)
                    let (Some(gl), Some(gr)) = (self.env.lookup_global("bool::and_left"), self.env.lookup_global("bool::and_right")) else {
                        return Ok(None);
                    };
                    let (and_left, and_right) = (mk::global(gl), mk::global(gr));
                    // h_k : e_k = true
                    let mut hk = Vec::new();
                    let mut rest_proof = self.f.scope.var(lh2);
                    for k in 0..n {
                        if k + 1 == n {
                            hk.push(rest_proof.clone());
                        } else {
                            let (a, b) = (es[k].clone(), conj(k + 1, self));
                            hk.push(mk::apps(and_left.clone(), [(Rel::Rel, a.clone()), (Rel::Rel, b.clone()), (Rel::Irr, rest_proof.clone())]));
                            rest_proof = mk::apps(and_right.clone(), [(Rel::Rel, a), (Rel::Rel, b), (Rel::Irr, rest_proof)]);
                        }
                    }
                    // p_k : x_k = y_k; then rebuild `C x.. = C y..`
                    if !pxs.is_empty() {
                        // with `Irr` fields: the congruence generalizes them
                        let mut eqs = Vec::new();
                        for k in 0..n {
                            let lemma = self.field_eq_lemma(&fts[k], true).unwrap();
                            eqs.push(mk::apps(lemma, [(Rel::Rel, self.f.scope.var(xs[k])), (Rel::Rel, self.f.scope.var(ys[k])), (Rel::Irr, hk[k].clone())]));
                        }
                        let (xv, yv): (Vec<Tm>, Vec<Tm>) = (xs.iter().map(|l| self.f.scope.var(*l)).collect(), ys.iter().map(|l| self.f.scope.var(*l)).collect());
                        let (pv, qv): (Vec<Tm>, Vec<Tm>) = (pxs.iter().map(|l| self.f.scope.var(*l)).collect(), pys.iter().map(|l| self.f.scope.var(*l)).collect());
                        let acc = self.ctor_congruence(ind, ka as u32, &[], &xv, &yv, &pv, &qv, &eqs, span)?;
                        self.f.scope = saved2;
                        inner_arms.push(Arm { names: decl.ctors[kb].fields.iter().map(|f| f.0.clone()).collect(), body: mk::lam("h", Rel::Irr, h2ty, acc) });
                        continue;
                    }
                    let mut acc = mk::refl(st.clone(), ca2.clone());
                    for k in 0..n {
                        let lemma = self.field_eq_lemma(&fts[k], true).unwrap();
                        let pk = mk::apps(lemma, [(Rel::Rel, self.f.scope.var(xs[k])), (Rel::Rel, self.f.scope.var(ys[k])), (Rel::Irr, hk[k].clone())]);
                        let fty = self.ty(&fts[k], span)?;
                        // motive z. C x.. = C y_0..y_{k-1} z x_{k+1}..  (in the context + z)
                        let sh = |t: Tm| sandblaster_kernel::util::shift(&t, 1);
                        let mut margs = Vec::new();
                        for j in 0..n {
                            margs.push(if j < k { sh(self.f.scope.var(ys[j])) } else if j == k { mk::var(0) } else { sh(self.f.scope.var(xs[j])) });
                        }
                        let motive = mk::eq(sh(st.clone()), sh(ca2.clone()), mk::ctor(ind, ka as u32, vec![], margs));
                        acc = Rc::new(Term::Transport { ty: fty, lhs: self.f.scope.var(xs[k]), rhs: self.f.scope.var(ys[k]), eq: pk, motive, val: acc });
                    }
                    let _ = conj;
                    mk::lam("h", Rel::Irr, h2ty, acc)
                };
                self.f.scope = saved2;
                inner_arms.push(Arm { names: decl.ctors[kb].fields.iter().map(|f| f.0.clone()).collect(), body });
            }
            // inner match on `b`: motive `b'. Π(.h : eq (C x..) b' = true). C x.. = b'`
            // `ca` was built before `h` was pushed; the match lives after it,
            // its motive binds `b'`, the motive's Π binds `h`
            let sh = |t: &Tm, n: i64| sandblaster_kernel::util::shift(t, n);
            let inner_motive = mk::pi("h", Rel::Irr, mk::eq(sh(&bool_t, 2), eq_app(sh(&ca, 2), mk::var(0)), sh(&tru, 2)), mk::eq(sh(&st, 3), sh(&ca, 3), mk::var(1)));
            let inner = Rc::new(Term::Match { ind, params: vec![], scrut: self.f.scope.var(lb), motive: inner_motive, arms: inner_arms });
            let body = mk::lam("h", Rel::Irr, h1ty, mk::apps(inner, [(Rel::Irr, mk::var(0))]));
            self.f.scope = saved;
            outer_arms.push(Arm { names: decl.ctors[ka].fields.iter().map(|f| f.0.clone()).collect(), body });
        }
        let sh1 = |t: &Tm| sandblaster_kernel::util::shift(t, 1);
        let outer_motive = mk::pi("h", Rel::Irr, mk::eq(sh1(&bool_t), eq_app(mk::var(0), sh1(&self.f.scope.var(lb))), sh1(&tru)), mk::eq(sandblaster_kernel::util::shift(&st, 2), mk::var(1), sandblaster_kernel::util::shift(&self.f.scope.var(lb), 2)));
        let outer = Rc::new(Term::Match { ind, params: vec![], scrut: self.f.scope.var(la), motive: outer_motive, arms: outer_arms });
        let proof = mk::apps(outer, [(Rel::Irr, self.f.scope.var(lh))]);
        let ty = pi_tele(&binders, target);
        let lam = lam_tele(&binders, proof);
        let failed = self.f.failed;
        let g = self.add_definition(&name, DefKind::Lemma, Some(id), ty, lam, Recursion::None, 3, false, failed, span)?;
        Ok(if failed { None } else { Some(g) })
    }

    /// `S::eq_complete : Π(a b : S)(.h : Eq(S, a, b)). Eq(Bool, S::eq a b,
    /// true)`: transport of `eq a a = true`, which holds by a match on `a`
    /// and the fields' completeness lemmas (the conjunction of `true`s
    /// computes to `true`; each conjunct is rewritten by a transport).
    fn derive_eq_complete(&mut self, id: ItemId, ind: sandblaster_kernel::term::IndId, eqg: GlobalId, self_ty: &Ty, span: Span) -> R<Option<GlobalId>> {
        let krate = self.krate;
        let name = format!("{}::eq_complete", krate.item(id).path);
        let nctors = self.ctor_count(self_ty, span)?;
        let mut field_tys = Vec::new();
        for k in 0..nctors {
            let ftys = self.ctor_field_tys(self_ty, k as u32, span)?;
            for ft in &ftys {
                if self.field_eq_lemma(ft, false).is_none() {
                    return Ok(None);
                }
            }
            field_tys.push(ftys);
        }
        self.f = FnState::new(name.clone(), Some(id), &[], span);
        self.f.mode = super::Mode::Proof;
        let st = self.ty(self_ty, span)?;
        let bool_t = mk::bool_ty(self.p.bool_);
        let tru = self.bool_lit(true);
        let eq_app = |a: Tm, b: Tm| mk::apps(mk::global(eqg), [(Rel::Rel, a), (Rel::Rel, b)]);
        let la = self.push("a", Rel::Rel, &st, None)?;
        let lb = self.push("b", Rel::Rel, &st, None)?;
        let hty = mk::eq(st.clone(), self.f.scope.var(la), self.f.scope.var(lb));
        let lh = self.push("h", Rel::Irr, &hty, None)?;
        let binders = vec![
            TBinder { name: "a".into(), rel: Rel::Rel, ty: st.clone() },
            TBinder { name: "b".into(), rel: Rel::Rel, ty: st.clone() },
            TBinder { name: "h".into(), rel: Rel::Irr, ty: hty },
        ];
        let target = mk::eq(bool_t.clone(), eq_app(self.f.scope.var(la), self.f.scope.var(lb)), tru.clone());
        let decl = self.env.inductive_decl(ind).ok_or_else(|| super::ElabError { span, msg: "unknown inductive".into(), kind: super::ErrKind::Internal })?;
        let sym = mk::global(self.p.g("eq::sym"));
        let mut arms = Vec::new();
        for ka in 0..nctors {
            let saved = self.f.scope.clone();
            let mut xs = Vec::new();
            for ft in &field_tys[ka] {
                let t = self.ty(ft, span)?;
                xs.push(self.push("x", Rel::Rel, &t, None)?);
            }
            self.push_irr_fields(ind, ka, &xs, "p")?;
            let fts = field_tys[ka].clone();
            let n = fts.len();
            let mut es = Vec::new();
            for (k, ft) in fts.iter().enumerate() {
                es.push(self.eq_at(ft, self.f.scope.var(xs[k]), self.f.scope.var(xs[k]), &[], span)?);
            }
            // G(z_0..z_{n-1}) = Eq(Bool, and(z_0, and(z_1, ..)), true)
            let g_of = |zs: &[Tm], me: &Self| -> Tm {
                let mut acc: Option<Tm> = None;
                for z in zs.iter().rev() {
                    acc = Some(match acc {
                        None => z.clone(),
                        Some(r) => me.and(z.clone(), r),
                    });
                }
                mk::eq(mk::bool_ty(me.p.bool_), acc.unwrap_or_else(|| me.bool_lit(true)), me.bool_lit(true))
            };
            let mut acc = mk::refl(bool_t.clone(), tru.clone());
            for k in 0..n {
                let lemma = self.field_eq_lemma(&fts[k], false).unwrap();
                let fty = self.ty(&fts[k], span)?;
                let xk = self.f.scope.var(xs[k]);
                let qk = mk::apps(lemma, [(Rel::Rel, xk.clone()), (Rel::Rel, xk.clone()), (Rel::Irr, mk::refl(fty, xk.clone()))]);
                let qk_sym = mk::apps(sym.clone(), [(Rel::Rel, bool_t.clone()), (Rel::Rel, es[k].clone()), (Rel::Rel, tru.clone()), (Rel::Rel, qk)]);
                let sh = |t: &Tm| sandblaster_kernel::util::shift(t, 1);
                let zs: Vec<Tm> = (0..n).map(|j| if j < k { sh(&es[j]) } else if j == k { mk::var(0) } else { sh(&self.bool_lit(true)) }).collect();
                let motive = g_of(&zs, self);
                acc = Rc::new(Term::Transport { ty: bool_t.clone(), lhs: tru.clone(), rhs: es[k].clone(), eq: qk_sym, motive, val: acc });
            }
            let _ = g_of;
            self.f.scope = saved;
            arms.push(Arm { names: decl.ctors[ka].fields.iter().map(|f| f.0.clone()).collect(), body: acc });
        }
        // eq a a = true by cases on `a`
        let sh1 = |t: &Tm| sandblaster_kernel::util::shift(t, 1);
        let refl_motive = mk::eq(sh1(&bool_t), eq_app(mk::var(0), mk::var(0)), sh1(&tru));
        let refl_a = Rc::new(Term::Match { ind, params: vec![], scrut: self.f.scope.var(la), motive: refl_motive, arms });
        // transport(S, a, b, h, z. eq a z = true, refl_a)
        let tmotive = mk::eq(sh1(&bool_t), eq_app(sh1(&self.f.scope.var(la)), mk::var(0)), sh1(&tru));
        let proof = Rc::new(Term::Transport { ty: st.clone(), lhs: self.f.scope.var(la), rhs: self.f.scope.var(lb), eq: self.f.scope.var(lh), motive: tmotive, val: refl_a });
        let ty = pi_tele(&binders, target);
        let lam = lam_tele(&binders, proof);
        let failed = self.f.failed;
        let g = self.add_definition(&name, DefKind::Lemma, Some(id), ty, lam, Recursion::None, 3, false, failed, span)?;
        Ok(if failed { None } else { Some(g) })
    }

    /// Pushes the `Irr` fields of constructor `ci` of `ind` (a
    /// non-generic user type) after its relevant fields at levels `xs`
    /// (arm binders; their types by substitution); returns their levels.
    fn push_irr_fields(&mut self, ind: sandblaster_kernel::term::IndId, ci: usize, xs: &[u32], name: &str) -> R<Vec<u32>> {
        let decl = self.env.inductive_decl(ind).ok_or_else(|| super::ElabError { span: self.f.span, msg: "unknown inductive".into(), kind: super::ErrKind::Internal })?;
        let mut out = Vec::new();
        for (_, r, fty) in decl.ctors[ci].fields.iter().skip(xs.len()) {
            if *r != Rel::Irr {
                break;
            }
            let mut args: Vec<Tm> = xs.iter().map(|l| self.f.scope.var(*l)).collect();
            args.extend(out.iter().map(|l| self.f.scope.var(*l)));
            let t = super::tm::subst_closed(fty, &args);
            out.push(self.push(name, Rel::Irr, &t, None)?);
        }
        Ok(out)
    }

    /// `Eq(D, C(ps; x̄, p̄), C(ps; ȳ, q̄))` from `eqs[k] : Eq(Aₖ, xₖ, yₖ)` for
    /// the relevant fields of constructor `ci` (terms at the current depth;
    /// `p̄`, `q̄` its `Irr` fields, §15.3): transports along each equation of
    /// `Π(r̄ :Irr I(y₀..yₖ₋₁, z, xₖ₊₁..)). Eq(D, C(x̄, p̄), C(y₀..yₖ₋₁, z, xₖ₊₁.., r̄))`
    /// — the `Irr` fields generalized, since their types change with the
    /// relevant fields — starting from `λr̄. refl` (conversion skips `Irr`
    /// constructor fields), applied to `q̄` at the end.
    #[allow(clippy::too_many_arguments)]
    pub fn ctor_congruence(&mut self, ind: sandblaster_kernel::term::IndId, ci: u32, params: &[Tm], xs: &[Tm], ys: &[Tm], ps: &[Tm], qs: &[Tm], eqs: &[Tm], span: Span) -> R<Tm> {
        super::tm::ctor_congruence_term(&self.env, ind, ci, params, xs, ys, ps, qs, eqs).ok_or_else(|| super::ElabError { span, msg: "unknown inductive".into(), kind: super::ErrKind::Internal })
    }

    /// `match a { C_k(xs) => match b { C_k(ys) => fields equal, _ => false } }`.
    #[allow(clippy::too_many_arguments)]
    fn enum_eq_body(&mut self, self_ty: &Ty, ind: sandblaster_kernel::term::IndId, n: u32, la: u32, lb: u32, param_eqs: &[u32], span: Span) -> R<Tm> {
        let nctors = self.ctor_count(self_ty, span)?;
        let bool_t = mk::bool_ty(self.p.bool_);
        let params_at = |me: &Self| -> Vec<Tm> { (0..n).map(|i| me.f.scope.var(i)).collect() };
        let decl = self.env.inductive_decl(ind).ok_or_else(|| super::ElabError { span, msg: "unknown inductive".into(), kind: super::ErrKind::Internal })?;
        let mut outer_arms = Vec::new();
        for ka in 0..nctors {
            let saved = self.f.scope.clone();
            let ftys = self.ctor_field_tys(self_ty, ka as u32, span)?;
            let mut xs = Vec::new();
            for ft in &ftys {
                let t = self.ty(ft, span)?;
                xs.push(self.push("x", Rel::Rel, &t, None)?);
            }
            let mut inner_arms = Vec::new();
            for kb in 0..nctors {
                let saved2 = self.f.scope.clone();
                let ftys_b = self.ctor_field_tys(self_ty, kb as u32, span)?;
                let mut ys = Vec::new();
                for ft in &ftys_b {
                    let t = self.ty(ft, span)?;
                    ys.push(self.push("y", Rel::Rel, &t, None)?);
                }
                let body = if ka == kb {
                    let mut acc: Option<Tm> = None;
                    for (j, ft) in ftys.iter().enumerate().rev() {
                        let (xv, yv) = (self.f.scope.var(xs[j]), self.f.scope.var(ys[j]));
                        let e = self.eq_at(ft, xv, yv, param_eqs, span)?;
                        acc = Some(match acc {
                            None => e,
                            Some(r) => self.and(e, r),
                        });
                    }
                    acc.unwrap_or_else(|| self.bool_lit(true))
                } else {
                    self.bool_lit(false)
                };
                self.f.scope = saved2;
                inner_arms.push(Arm { names: decl.ctors[kb].fields.iter().map(|f| f.0.clone()).collect(), body });
            }
            let d = self.depth();
            let inner = Rc::new(Term::Match { ind, params: params_at(self), scrut: self.f.scope.var(lb), motive: sandblaster_kernel::util::shift(&bool_t, 1), arms: inner_arms });
            let _ = d;
            self.f.scope = saved;
            outer_arms.push(Arm { names: decl.ctors[ka].fields.iter().map(|f| f.0.clone()).collect(), body: inner });
        }
        Ok(Rc::new(Term::Match { ind, params: params_at(self), scrut: self.f.scope.var(la), motive: sandblaster_kernel::util::shift(&bool_t, 1), arms: outer_arms }))
    }
}
