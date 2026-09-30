//! Refinement (DESIGN.md §15.2, §15.3; stage **S1**): the `f::refines`
//! lemma of every `#[refines]` exec function, its proof, and its use as a
//! fact at call sites.
//!
//! # The statement (`ObligationKind::Refines`)
//!
//! For `#[refines(s)]` on `fn f<T..>(x̄: Ā) -> R` with `requires` `Req_f`
//! (and the depth hypothesis of `#[decreases(.., max)]`):
//!
//! ```text
//! f::refines : Π(T..)(x̄ : Ā)(h̄ : Req_f x̄)[(hd : P x̄)].
//!                 Eq(⟦V⟧, α_R(f x̄ h̄), s(ᾱ x̄; p̄))
//! ```
//!
//! * `ᾱ x̄` are the spec arguments: the view coercions `αᵢ(Aᵢ ↦ Vᵢ) xᵢ`
//!   of the parameters, positionally (the bare form), or the explicit
//!   argument map `#[refines(s(e₁, …, eₙ))]` (ghost expressions over the
//!   parameters, coerced to the spec's parameter types by the typechecker);
//!   `V` is the spec's result type and `α_R` the coercion of `f`'s result to
//!   it (state passing `fn m(self, ..) -> (Self, R)` is the tuple case:
//!   componentwise).
//! * `p̄` are the proofs of `s`'s `Irr` binders (its `requires` and the
//!   `Nat` bounds of its parameters) at `ᾱ x̄`: **obligations** proven from
//!   `Req_f` and the domain — never hypotheses. With no `requires` and no
//!   domain (every boundary function, DESIGN.md §3.1, §15.2 "total at the
//!   boundary") the spec must be total on the function's input type.
//! * `hd : P x̄` is the hypothesis of `#[refines(s, domain = P)]` (internal
//!   functions only; the boundary rule rejects it on `pub` functions).
//! * Methods of a struct `S` with `#[represents(|s, a: A| Rel)]` use the
//!   simulation form (§15.3): a constructor-like method (no `self`,
//!   returns `S`) establishes `Rel(ret, s(ᾱ x̄))`; a method with `self`
//!   gets `(a : A)(hr : Rel(self, a))` and proves `Rel(ret, s(a, ᾱ x̄'))`
//!   (`S → S`), `Rel(ret.0, s(..).0) ∧ α(ret.1) = s(..).1` (`S → (S, R)`), or
//!   `α(ret) = s(a, ᾱ x̄')` (any other result).
//!
//! The lemma has the telescope of `f::ensures` (hypotheses relevant; it is
//! used in irrelevant positions only), so at every call of `f` it is a fact
//! `h_ens : Eq(V, α(f ā), s(ᾱ ā))` exactly like `ensures` (§7.3); a
//! function with both `#[ensures]` and `#[refines]` gets both facts, i.e.
//! their conjunction.
//!
//! # The proof
//!
//! Like `f::ensures`: the body of `f` is walked (`Elab::walk_body`: lets,
//! matches, post-loop facts of loop helpers in context) and the goal is
//! proven at every tail value by the prover chain, with the induction
//! hypotheses of recursive calls (measure recursion with `f`'s measure;
//! not for the domain and simulation forms, whose extra hypotheses the
//! recursive calls cannot supply — use a proof item there). Functions with
//! loops unfold by `delta`. Or by the script of a `#[proof(refines = f)]`
//! item (PROOF.rs; parameters identified with `f`'s), elaborated against the
//! same statement.
//!
//! # Determinacy (§15.2)
//!
//! A checked refinement determines `f` — and makes it **established** for
//! spec closure (§15.1) — only if the result coercion is injective
//! (`Elab::view_injective`), there is no domain, and it is not the
//! simulation form (which needs `Abstract(S)`, S2). Otherwise the record
//! says "refines `s` up to view(T)" ([`RefinesRecord::up_to`]) and §15.5
//! (S3) applies.
//!
//! `#[refines]` on an `#[implements]` variant is rejected by the
//! typechecker (variants inherit through `VariantEquiv`).

use std::rc::Rc;

use sandblaster_kernel::term::{DefKind, GlobalId, PrimOp, Recursion, Rel, Term, Tm};
use sandblaster_kernel::util::{mk, shift};

use super::ensures::{strip_lams, WalkGoal};
use super::items::{lam_tele, pi_tele, TBinder};
use super::{internal, DefStatus, Elab, ElabError, ErrKind, FnState, Mode, R};
use crate::diag::{DiagKind, Diagnostic};
use crate::hir::{FnDef, ItemId, ItemKind, ProofOf, Refines, Represents, Ty, View};
use crate::prover::{FactOrigin, ObligationKind};
use crate::span::Span;

/// The shape of a refinement statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefinesForm {
    /// `Eq(V, α(f x̄), s(ᾱ x̄))` (state passing is its tuple case).
    Plain,
    /// `#[represents]`: a constructor-like method establishes the relation.
    RepConstructor,
    /// `#[represents]`: `S → S` preserves it.
    RepPreserve,
    /// `#[represents]`: `S → (S, R)` preserves it and refines `R`.
    RepStatePassing,
    /// `#[represents]`: a non-`S` result refines through it.
    RepObserver,
}

/// One refinement lemma `f::refines` (for the report and the surface).
#[derive(Clone, Debug)]
pub struct RefinesRecord {
    /// The exec function.
    pub item: ItemId,
    /// The spec function it refines.
    pub spec: ItemId,
    /// The kernel lemma, once proven.
    pub lemma: Option<GlobalId>,
    pub status: DefStatus,
    /// How it was proven: `walk` (the body walk and the prover chain) or
    /// the path of the `#[proof(refines = ..)]` item.
    pub proof: String,
    pub form: RefinesForm,
    /// `#[refines(s, domain = P)]`: the spec sheet prints `WHEN P`.
    pub domain: bool,
    /// Why the refinement does not determine `f` (§15.2): "refines `s` up
    /// to view(T)" and the like; `None` when it does (identity or
    /// injective views, no domain, not the simulation form).
    pub up_to: Option<String>,
    /// Why it determines `f` when `up_to` is `None` (S2): an identity or
    /// injective result view (with the `view_inj` lemmas used), `Abstract(T)`
    /// for a lossy view (determines, does not establish), or `Abstract(S)`
    /// with an established representation relation. Printed on the spec
    /// sheet and in the report; meaningful for checked records only.
    pub determined_by: Option<String>,
    /// The kernel statement, printed (for the report and the spec sheet).
    pub statement: String,
}

/// How the goal at a value `v` of `f`'s result type is built.
#[derive(Clone)]
enum GoalShape {
    /// `Eq(⟦to⟧, α(v), spec_app)`.
    Plain { from: Ty, to: Ty },
    /// `Rel(v, spec_app)`.
    Rep { rep: Tm },
    /// `Σ(_ : Rel(π₀ v, π₀ spec_app)). Eq(⟦to⟧, α(π₁ v), π₁ spec_app)`.
    RepPair { rep: Tm, s_ty: Ty, a_ty: Ty, from: Ty, to: Ty },
}

/// The statement's pieces, at the depth `base` (after every binder).
#[derive(Clone)]
struct StmtGoal {
    shape: GoalShape,
    spec_app: Tm,
    base: u32,
    /// The target, when the lockstep can meet it (a spec function with a
    /// body), and whether it is a model (`#[model]` module).
    lockstep: Option<(GlobalId, bool)>,
}

/// The goal of the body walk (DESIGN.md §15.2 "proven like `ensures`").
struct RefGoal {
    st: Rc<StmtGoal>,
    span: Span,
}

impl<'a> WalkGoal<'a> for RefGoal {
    fn goal(&mut self, el: &mut Elab<'a>, v: &Tm) -> R<Tm> {
        el.refines_goal_at(&self.st, v, self.span)
    }

    fn leaf(&mut self, el: &mut Elab<'a>, t: &Tm) -> R<Tm> {
        let d0 = el.depth();
        let (st, span, t0) = (self.st.clone(), self.span, t.clone());
        el.with_induction_hyps(t, &mut |s| {
            let d = s.depth();
            let t = shift(&t0, (d - d0) as i64);
            let goal = s.refines_goal_at(&st, &t, span)?;
            // the lockstep (layered proofs, `elab::lockstep`): first when
            // the target is a model (shaped like the code: the prover alone
            // would unfold it blindly), after the prover chain for any other
            // spec target with a body. A lockstep proof counts only if every
            // one of its obligations is proven; a failed one leaves its
            // report as a note of the refinement's unproven branch
            let model = st.lockstep.is_some_and(|(_, m)| m);
            if model && let Some(q) = s.lockstep_leaf(&goal, span)? {
                return Ok(q);
            }
            let report = if model { super::lockstep::take_failure() } else { None };
            let rec = s.save_records();
            let p = s.prove_relevant(ObligationKind::Refines, span, &goal)?;
            if s.records_proven_since(&rec) {
                return Ok(p);
            }
            let failed = s.split_records(&rec);
            if !model && st.lockstep.is_some() && let Some(q) = s.lockstep_leaf(&goal, span)? {
                return Ok(q);
            }
            let report = report.or_else(super::lockstep::take_failure);
            s.restore_records(&rec, failed);
            if let Some(r) = report
                && let Some(d) = s.diags.list.iter_mut().rev().find(|d| d.kind == DiagKind::Obligation)
            {
                d.notes.push((None, r));
            }
            Ok(p)
        })
    }

    fn eq_on_projections(&self) -> bool {
        true
    }
}

impl<'a> Elab<'a> {
    /// The goal of `st` at the value `v` (a term at the current depth).
    fn refines_goal_at(&mut self, st: &StmtGoal, v: &Tm, span: Span) -> R<Tm> {
        let k = (self.depth() - st.base) as i64;
        let app = shift(&st.spec_app, k);
        match &st.shape {
            GoalShape::Plain { from, to } => {
                let av = self.abstraction(from, to, v.clone(), span)?;
                let vt = self.ty(to, span)?;
                Ok(mk::eq(vt, av, app))
            }
            GoalShape::Rep { rep } => Ok(mk::apps(shift(rep, k), [(Rel::Rel, v.clone()), (Rel::Rel, app)])),
            GoalShape::RepPair { rep, s_ty, a_ty, from, to } => {
                let pair_ty = Ty::Tuple(vec![s_ty.clone(), from.clone()]);
                let (ind, params) = self.ind_of(&pair_ty, span)?;
                let st_tm = self.ty(s_ty, span)?;
                let rt_tm = self.ty(from, span)?;
                let v0 = self.proj(ind, params.clone(), v.clone(), 0, 2, st_tm);
                let v1 = self.proj(ind, params, v.clone(), 1, 2, rt_tm);
                let spec_pair = Ty::Tuple(vec![a_ty.clone(), to.clone()]);
                let (sind, sparams) = self.ind_of(&spec_pair, span)?;
                let at_tm = self.ty(a_ty, span)?;
                let to_tm = self.ty(to, span)?;
                let a0 = self.proj(sind, sparams.clone(), app.clone(), 0, 2, at_tm);
                let a1 = self.proj(sind, sparams, app, 1, 2, to_tm.clone());
                let rel = mk::apps(shift(rep, k), [(Rel::Rel, v0), (Rel::Rel, a0)]);
                let av1 = self.abstraction(from, to, v1, span)?;
                let eq = mk::eq(to_tm, av1, a1);
                Ok(mk::sigma("_", Rel::Rel, rel, shift(&eq, 1)))
            }
        }
    }

    /// `f::refines` right after `f` (unless a `#[proof(refines = f)]` item
    /// proves it: then it is built when that item is reached, after
    /// everything its script mentions).
    pub fn refines_after_fn(&mut self, id: ItemId, f: &'a FnDef, g: GlobalId) {
        if !self.s1.on || f.spec.refines.is_none() || f.spec.refines_proof.is_some() {
            return;
        }
        if let Err(e) = self.refines_def(id, f, g, None) {
            self.refines_failed(id, f, e);
        }
    }

    /// A `#[proof(refines = f)]` item: builds and proves `f::refines` with
    /// its script.
    pub fn refines_proof_item(&mut self, pid: ItemId, pf: &'a FnDef, p: &ProofOf) {
        if !self.s1.on {
            return;
        }
        let krate = self.krate;
        let target = p.target;
        let Some(f) = krate.fn_def(target) else { return };
        if f.spec.refines.is_none() {
            // reported by the validator's pairing
            return;
        }
        let g = match self.item_global(target, p.span) {
            Ok(g) => g,
            Err(e) => {
                self.refines_failed(target, f, e);
                return;
            }
        };
        if let Err(e) = self.refines_def(target, f, g, Some((pid, pf))) {
            self.refines_failed(target, f, e);
        }
    }

    fn refines_failed(&mut self, id: ItemId, f: &FnDef, e: ElabError) {
        let Some(r) = &f.spec.refines else { return };
        let path = self.krate.item(id).path.to_string();
        if e.kind != ErrKind::Deferred {
            let span = if e.span.is_dummy() { r.span } else { e.span };
            self.diag(Diagnostic::error(DiagKind::Elab, span, format!("`{path}::refines` could not be stated or proven: {}", e.msg)));
        }
        if !self.s1.refinements.iter().any(|x| x.item == id) {
            self.s1.refinements.push(RefinesRecord {
                item: id,
                spec: r.spec,
                lemma: None,
                status: DefStatus::Blocked(e.msg),
                proof: String::new(),
                form: RefinesForm::Plain,
                domain: r.domain.is_some(),
                up_to: None,
                determined_by: None,
                statement: String::new(),
            });
        }
    }

    /// Builds and proves `f::refines` (see the module docs).
    fn refines_def(&mut self, id: ItemId, f: &'a FnDef, g: GlobalId, proof: Option<(ItemId, &'a FnDef)>) -> R<()> {
        let krate = self.krate;
        let it = krate.item(id);
        let r: &'a Refines = f.spec.refines.as_ref().ok_or_else(|| ElabError { span: it.span, msg: "no #[refines]".into(), kind: ErrKind::Internal })?;
        let span = r.span;
        let name = format!("{}::refines", it.path);
        let spec_g = self.item_global(r.spec, span)?;
        let spec_f = krate.fn_def(r.spec).ok_or_else(|| ElabError { span, msg: "the spec is not a function".into(), kind: ErrKind::Internal })?;
        // a function (or spec) that reaches a definition that did not verify
        // is a placeholder there (a default value): the goal would be about
        // the default, not the code — report it as not checked instead
        if let Some(p) = self.placeholder_reached(&mk::global(g)).or_else(|| self.placeholder_reached(&mk::global(spec_g))) {
            self.diag(
                Diagnostic::error(DiagKind::Elab, span, format!("`{name}` was not checked: it depends on `{p}`, which did not verify"))
                    .note("the definition was replaced by a placeholder (a default value) so that the rest of the crate could be checked; a refinement goal through it would be about the placeholder, not the code — fix the errors above first"),
            );
            self.s1.refinements.push(RefinesRecord {
                item: id,
                spec: r.spec,
                lemma: None,
                status: DefStatus::Blocked(format!("depends on `{p}`, which did not verify")),
                proof: String::new(),
                form: RefinesForm::Plain,
                domain: r.domain.is_some(),
                up_to: None,
                determined_by: None,
                statement: String::new(),
            });
            return Ok(());
        }
        let ndiag0 = self.diags.list.len();
        self.f = FnState::new(name.clone(), Some(id), &f.locals, span);
        self.f.fdef = Some(f);
        self.f.mode = Mode::Proof;
        // f's telescope (the telescope of `f::ensures`)
        let (mut binders, pending) = self.fn_params(f, span)?;
        self.fn_requires(f, &mut binders, Rel::Rel)?;
        if let Some(dec) = &f.decreases
            && let Some(max) = dec.max
        {
            let m = self.pure_expr(&dec.measure)?;
            let w = self.width_of(&dec.measure.ty, dec.measure.span)?;
            let p = self.holds(mk::prim(PrimOp::Le(w), vec![m, mk::lit(w, max)], vec![]));
            let lvl = self.push("h_depth", Rel::Rel, &p, None)?;
            self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lvl), origin: FactOrigin::Requires, span: dec.measure.span });
            self.f.scope.fact_tys.insert(lvl, p.clone());
            binders.push(TBinder { name: "h_depth".into(), rel: Rel::Rel, ty: p });
        }
        let n_f = self.depth();
        let ngen = f.generics.len() as u32;
        // `f x̄ h̄` (exec requires are irrelevant binders of `f`)
        let rels = self.env.global_param_rels(g).unwrap_or_default();
        let mut app = mk::global(g);
        for (i, rl) in rels.iter().enumerate().take(n_f as usize) {
            app = Rc::new(Term::App { rel: *rl, fun: app, arg: self.f.scope.var(i as u32) });
        }
        // the domain hypothesis
        if let Some(d) = &r.domain {
            let p = self.prop(d)?;
            let lvl = self.push("h_domain", Rel::Rel, &p, None)?;
            self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lvl), origin: FactOrigin::LemmaHyp, span: d.span });
            self.f.scope.fact_tys.insert(lvl, p.clone());
            binders.push(TBinder { name: "h_domain".into(), rel: Rel::Rel, ty: p });
        }
        // the simulation form of a method of a `#[represents]` struct
        let rep = self.represents_of(f);
        let mut form = RefinesForm::Plain;
        let mut spec_args: Vec<Tm> = Vec::new();
        let mut first_param = 0usize;
        let mut rep_parts: Option<(Tm, Ty, Ty)> = None; // (rep applied to type args, S, A)
        if let Some((owner, rep_g, repr)) = rep {
            let sd_generics = match &krate.item(owner).kind {
                ItemKind::Struct(s) => s.generics.len(),
                _ => 0,
            };
            let s_ty = Ty::Adt(owner, f.generics.iter().take(sd_generics).enumerate().map(|(i, gp)| Ty::Param(i as u32, gp.name.clone())).collect());
            let mut rep_tm = mk::global(rep_g);
            for i in 0..sd_generics as u32 {
                rep_tm = mk::app(rep_tm, self.f.scope.var(i));
            }
            let a_ty = repr.abs_ty.clone();
            let ret_is_s = f.ret.peel_refs() == &s_ty;
            if f.receiver.is_some() {
                // (a : A)(hr : Rel(self, a))
                let at = self.ty(&a_ty, span)?;
                let la = self.push("a", Rel::Rel, &at, None)?;
                binders.push(TBinder { name: "a".into(), rel: Rel::Rel, ty: at });
                let self_v = self.f.scope.var(ngen);
                let hr_ty = mk::apps(rep_tm.clone(), [(Rel::Rel, self_v), (Rel::Rel, self.f.scope.var(la))]);
                let lh = self.push("h_rep", Rel::Rel, &hr_ty, None)?;
                self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lh), origin: FactOrigin::LemmaHyp, span });
                self.f.scope.fact_tys.insert(lh, hr_ty.clone());
                binders.push(TBinder { name: "h_rep".into(), rel: Rel::Rel, ty: hr_ty });
                if spec_f.params.first().map(|t| t.ty.peel_refs()) != Some(&a_ty) {
                    return Err(ElabError { span, msg: format!("the spec of a method of `{}` (which has `#[represents]`) takes the abstract state `{}` first", krate.item(owner).name, krate.ty_str(&a_ty)), kind: ErrKind::Unsupported });
                }
                spec_args.push(self.f.scope.var(la));
                first_param = 1;
                form = if ret_is_s {
                    RefinesForm::RepPreserve
                } else if matches!(&f.ret, Ty::Tuple(ts) if ts.len() == 2 && ts[0].peel_refs() == &s_ty) {
                    RefinesForm::RepStatePassing
                } else {
                    RefinesForm::RepObserver
                };
            } else if ret_is_s {
                form = RefinesForm::RepConstructor;
            }
            if form != RefinesForm::Plain {
                rep_parts = Some((rep_tm, s_ty, a_ty));
            }
        }
        // the spec arguments
        match &r.args {
            Some(es) => {
                if !spec_args.is_empty() {
                    return Err(ElabError { span, msg: "the explicit argument map is not supported on methods of a `#[represents]` struct (the abstract state is the spec's first argument)".into(), kind: ErrKind::Unsupported });
                }
                for e in es {
                    spec_args.push(self.pure_expr(e)?);
                }
                // the argument map is part of the specification side: it
                // must be spec-closed (DESIGN.md §15.1)
                let args_now = spec_args.clone();
                let stop: Vec<GlobalId> = vec![];
                self.spec_closure_check(id, "the explicit argument map of `#[refines]` on", &args_now, &stop, true, span);
            }
            None => {
                let want = spec_f.params.len() - spec_args.len();
                let have = f.params.len() - first_param;
                if want != have {
                    return Err(ElabError {
                        span,
                        msg: format!("`{}` takes {} argument(s) but `{}` passes {have}; write the argument map explicitly: `#[refines({}(..))]`", krate.item(r.spec).path, spec_f.params.len(), it.path, krate.item(r.spec).path),
                        kind: ErrKind::Unsupported,
                    });
                }
                let off = spec_args.len();
                for (j, p) in f.params.iter().enumerate().skip(first_param) {
                    let to = spec_f.params[off + j - first_param].ty.clone();
                    // a `#[ghost]` parameter: its projection of the ghost
                    // bundle (relevant in the lemma, §15.3)
                    let x = match (&p.pat.kind, p.ghost) {
                        (crate::hir::PatKind::Binding { local, .. }, true) => self.local_tm(*local, span)?,
                        _ => self.f.scope.var(ngen + j as u32),
                    };
                    spec_args.push(self.abstraction(&p.ty, &to, x, span)?);
                }
            }
        }
        // `s(ᾱ x̄; p̄)`: the spec's `Irr` binders are obligations here
        let nspec_gen = spec_f.generics.len();
        let mut rel_args: Vec<Tm> = Vec::new();
        if nspec_gen > 0 {
            if nspec_gen != f.generics.len() {
                return Err(ElabError { span, msg: format!("a generic spec refines at the identity on the type parameters: `{}` has {} type parameter(s), `{}` {}", krate.item(r.spec).path, nspec_gen, it.path, f.generics.len()), kind: ErrKind::Unsupported });
            }
            for i in 0..nspec_gen as u32 {
                rel_args.push(self.f.scope.var(i));
            }
        }
        rel_args.extend(spec_args);
        let spec_ty = self.env.global_type(spec_g).ok_or_else(|| ElabError { span, msg: "spec without type".into(), kind: ErrKind::Internal })?;
        let (spec_app, _, _) = self.apply_tele(&spec_ty, rel_args, Some(mk::global(spec_g)), None, &|_| ObligationKind::CalleeRequires(spec_g), span)?;
        let base = self.depth();
        let arity = base;
        let shape = match (&form, rep_parts) {
            (RefinesForm::Plain | RefinesForm::RepObserver, _) => GoalShape::Plain { from: f.ret.clone(), to: spec_f.ret.clone() },
            (RefinesForm::RepConstructor | RefinesForm::RepPreserve, Some((rep_tm, _, _))) => GoalShape::Rep { rep: rep_tm },
            (RefinesForm::RepStatePassing, Some((rep_tm, s_ty, a_ty))) => {
                let (Ty::Tuple(fr), Ty::Tuple(sr)) = (&f.ret, &spec_f.ret) else {
                    return Err(ElabError { span, msg: "a state-passing refinement needs a pair result `(Self, R)` and a pair spec result `(A, R')`".into(), kind: ErrKind::Unsupported });
                };
                if sr.len() != 2 {
                    return Err(ElabError { span, msg: "a state-passing refinement needs a pair spec result `(A, R')`".into(), kind: ErrKind::Unsupported });
                }
                GoalShape::RepPair { rep: rep_tm, s_ty, a_ty, from: fr[1].clone(), to: sr[1].clone() }
            }
            _ => return internal(span, "refinement form without a representation relation"),
        };
        let lockstep = (matches!(shape, GoalShape::Plain { .. }) && self.lockstep_target(spec_g)).then(|| (spec_g, self.is_model_fn(spec_g)));
        let st = Rc::new(StmtGoal { shape, spec_app, base, lockstep });
        let goal = self.refines_goal_at(&st, &shift(&app, (base - n_f) as i64), span)?;
        let ty = pi_tele(&binders, goal.clone());
        // determinacy (§15.2); a spec that is not spec-closed (reported at the
        // spec, §15.1) determines nothing
        let verdict = self.refines_verdict(r, f, spec_f, &form);
        let (mut up_to, determined_by) = match verdict {
            Ok(why) => (None, Some(why)),
            Err(why) => (Some(why), None),
        };
        // only an injective view establishes `f` for spec closure (§15.1);
        // `Abstract(T)` determines without establishing (spec code may read
        // what the view hides)
        let injective = form == RefinesForm::Plain && r.domain.is_none() && self.view_injective(&f.ret, &spec_f.ret).is_none();
        if let Some(bad) = self.closure_violation(&[mk::global(spec_g)], &[]) {
            let n = self.env.global_name(bad).map(|n| n.to_string()).unwrap_or_default();
            up_to = Some(format!("the specification `{}` depends on the exec function `{n}` (not spec-closed)", krate.item(r.spec).path));
        }
        let statement = self.show_tm(&ty);
        // the proof
        let proof_desc;
        let (body, recursion) = match proof {
            Some((pid, pf)) => {
                proof_desc = krate.item(pid).path.to_string();
                let steps = match &pf.body {
                    crate::hir::FnBody::Script(s) => s,
                    _ => return internal(span, "a proof item without a script"),
                };
                self.refines_script(pid, pf, f, steps, &pending, goal.clone(), &ty, arity, span)?
            }
            None => {
                proof_desc = "walk".into();
                self.refines_walk(id, f, g, &st, n_f, arity, &ty, &app, span)?
            }
        };
        let lam = lam_tele(&binders, body);
        let failed = self.f.failed;
        let res = self.add_definition(&name, DefKind::Ensures, Some(id), ty, lam, recursion, arity, false, failed, span);
        let checked = res.is_ok() && self.defs.last().is_some_and(|d| d.name == name && d.status == DefStatus::Checked);
        let status = self.defs.iter().rev().find(|d| d.name == name).map(|d| d.status.clone()).unwrap_or(DefStatus::Unproven);
        if checked && up_to.is_none() && injective {
            self.s1.established.insert(g);
        }
        let unproven = status == DefStatus::Unproven;
        if unproven {
            self.refines_unproven_diag(ndiag0, &name, it.path.to_string(), krate.item(r.spec).path.to_string(), span, &proof_desc);
        }
        self.s1.refinements.push(RefinesRecord { item: id, spec: r.spec, lemma: res.as_ref().ok().copied().filter(|_| checked), status, proof: proof_desc, form, domain: r.domain.is_some(), determined_by: determined_by.filter(|_| up_to.is_none()), up_to, statement });
        match res {
            // the unproven obligations are reported with their goals
            Err(_) if unproven => Ok(()),
            r => r.map(|_| ()),
        }
    }

    /// The `error[refines-unproven]` of an unproven refinement (DESIGN.md
    /// §15.10): the per-branch `[refines]` obligation errors reported since
    /// `ndiag0` are folded into one error at the attribute, each branch a
    /// note (goal and facts in surface syntax, what blocked it), with a
    /// suggestion chosen by what blocked the branches.
    fn refines_unproven_diag(&mut self, ndiag0: usize, lemma: &str, fpath: String, spath: String, span: Span, proof: &str) {
        let msg = format!("unproven obligation [refines] in `{lemma}`");
        let (mut branches, mut keep) = (Vec::new(), Vec::new());
        for d in self.diags.list.drain(ndiag0.min(self.diags.list.len())..) {
            if d.kind == DiagKind::Obligation && d.msg == msg { branches.push(d) } else { keep.push(d) }
        }
        self.diags.list.extend(keep);
        if branches.is_empty() {
            return;
        }
        let total = self.obligations.iter().filter(|o| o.def == lemma && o.kind == ObligationKind::Refines).count().max(branches.len());
        let mut d = Diagnostic::error(DiagKind::RefinesUnproven, span, format!("`{fpath}` is not proven to refine `{spath}`: {} of {total} branch(es) unproven", branches.len()));
        let mut blocked = String::new();
        for (i, b) in branches.iter().enumerate() {
            let at = if b.span.is_dummy() || b.span == span { String::new() } else { format!(" (at line {})", b.span.lo.0) };
            let goal = b.goal.clone().unwrap_or_default();
            let stuck: Vec<&str> = b.notes.iter().filter_map(|(_, n)| n.strip_prefix("stuck: ")).take(3).collect();
            // what a closer reported (`bv()`: the first differing element)
            let closer: Vec<&str> = b.notes.iter().filter_map(|(_, n)| n.strip_prefix("tried: ")).filter(|n| n.starts_with("`bv()`") || n.starts_with("`exact`")).take(2).collect();
            for x in &stuck {
                blocked.push_str(x);
                blocked.push('\n');
            }
            blocked.push_str(&goal);
            let mut note = format!("branch {}{at}:\n    {}", i + 1, goal.replace('\n', "\n    "));
            if !stuck.is_empty() {
                note.push_str(&format!("\n    stuck (kernel form): {}", stuck.join("; ")));
            }
            for c in &closer {
                note.push_str(&format!("\n    {c}"));
                blocked.push_str(c);
            }
            // the lockstep's report (layered proofs): where code and target differ
            for (_, n) in b.notes.iter().filter(|(_, n)| n.starts_with("lockstep with ")) {
                note.push_str(&format!("\n    {}", n.replace('\n', "\n    ")));
            }
            d = d.note(note);
        }
        d = d.note(self.refines_suggestion(&blocked, &fpath, proof));
        self.diag(d);
    }

    /// What to try, from what blocked the branches (surface text).
    fn refines_suggestion(&self, blocked: &str, fpath: &str, proof: &str) -> String {
        let item = if proof == "walk" { format!("add `#[proof(refines = {fpath})]` in PROOF.rs") } else { format!("in `{proof}`") };
        if blocked.contains("from_be_bytes") || blocked.contains("from_le_bytes") {
            return format!("the goal needs the positional value of bytes: state it as a lemma (`u16::from_be_bytes([a, b]) == (a as u16) * 256u16 + (b as u16)`, proven by `bv()`) and call it — {item} with `unfold({fpath})` and the lemma call before `follows()`");
        }
        // an opaque exec function (loops, buffers, codec readers) is used
        // through its contract only
        let opaque: Vec<String> = self
            .defs
            .iter()
            .filter(|x| x.kind == DefKind::Exec)
            .filter_map(|x| x.global)
            .filter(|g| self.env.global_opaque(*g) == Some(true))
            .filter_map(|g| self.env.global_name(g).map(|n| n.to_string()))
            .filter(|n| n != fpath && blocked.contains(&format!("{n}(")))
            .collect();
        if let Some(g) = opaque.first() {
            return format!("`{g}` is opaque in proofs (a loop, a buffer builder or a codec reader: DESIGN.md §5.6), so its calls are known only through its contract: give it `#[refines]` or `#[ensures]`, or {item} with `unfold({g})`");
        }
        if blocked.contains("`bv()`") {
            return "`bv()` found the sides different modulo word algebra (the element above): check the implementation against the specification at that element — a constant, an operator or an index — or prove the step with an intermediate lemma".to_string();
        }
        if ["wrapping_", "rotate_", " ^ ", " & ", " | ", ">>", "<<"].iter().any(|w| blocked.contains(w)) {
            return format!("the goal is word arithmetic: {item} ending in `bv()` (the kernel's word normalizer, DESIGN.md §9.8)");
        }
        format!("{item}: `unfold({fpath});` then case analysis (`if`/`match`), lemma calls or `assert`s where a branch needs a fact, and `follows()` (DESIGN.md §15.2)")
    }

    /// Whether a refinement determines its function (see the module docs):
    /// `Ok(why it does)` or `Err(why it does not)` — the latter the "up to"
    /// text of [`RefinesRecord::up_to`].
    fn refines_verdict(&self, r: &Refines, f: &FnDef, spec_f: &FnDef, form: &RefinesForm) -> Result<String, String> {
        let sp = self.krate.item(r.spec).path.to_string();
        if r.domain.is_some() {
            return Err(format!("refines `{sp}` only on its domain (`domain = ..`)"));
        }
        match form {
            // an injective view, or a lossy one on an `Abstract` type (§15.2,
            // §15.3)
            RefinesForm::Plain => self.view_determinacy(&f.ret, &spec_f.ret).map_err(|v| format!("refines `{sp}` up to {v}")),
            _ => Err(format!("refines `{sp}` through a representation relation (determinacy needs `Abstract(T)` and a constructor-like method that establishes the relation)")),
        }
    }

    /// The owner's `#[represents]`, when `f` is a method of such a struct.
    fn represents_of(&self, f: &FnDef) -> Option<(ItemId, GlobalId, &'a Represents)> {
        let owner = f.owner?;
        let g = *self.s1.represents.get(&owner)?;
        match &self.krate.item(owner).kind {
            ItemKind::Struct(s) => s.represents.as_ref().map(|r| (owner, g, r)),
            _ => None,
        }
    }

    /// The body walk (see the module docs); returns the proof and the
    /// recursion of the lemma.
    #[allow(clippy::too_many_arguments)]
    fn refines_walk(&mut self, id: ItemId, f: &'a FnDef, g: GlobalId, st: &Rc<StmtGoal>, n_f: u32, arity: u32, ty: &Tm, app: &Tm, span: Span) -> R<(Tm, Recursion)> {
        let body_tm = self.env.global_body(g).ok_or_else(|| ElabError { span, msg: "the function has no body".into(), kind: ErrKind::Internal })?;
        let extra = arity - n_f;
        let inner = shift(&strip_lams(&body_tm, n_f), extra as i64);
        let recursive = super::tm::any_node(&body_tm, &mut |n| matches!(n, Term::Global(h) if *h == g));
        let opaque = self.env.global_opaque(g) == Some(true);
        let mut recursion = Recursion::None;
        if recursive && extra == 0 {
            let (m, w) = match &f.decreases {
                Some(dec) => (self.pure_expr(&dec.measure)?, self.width_of(&dec.measure.ty, dec.measure.span)?),
                None => match self.infer_measure_pub(id, f) {
                    Some(x) => x,
                    None => return super::unsupported(f.sig_span, "cannot infer a termination measure for the refinement proof; add `#[decreases(e)]`"),
                },
            };
            self.f.rec = Some(super::RecInfo { item: None, ty: ty.clone(), arity, measure: Some((m.clone(), w)) });
            self.ens_rec = Some((g, n_f));
            recursion = Recursion::Measure { measure: m };
        }
        let mut wg = RefGoal { st: st.clone(), span };
        let was = super::lockstep::IH_IN_CHOICES.with(|c| c.replace(st.lockstep.is_some()));
        let walked = self.walk_body(&inner, &mut wg);
        super::lockstep::IH_IN_CHOICES.with(|c| c.set(was));
        self.ens_rec = None;
        let mut proof = walked?;
        if recursive || opaque {
            // transport(R, body, f x h, sym(delta(f; x h)), z. G[z], proof)
            let app_here = shift(app, extra as i64);
            let args: Vec<Tm> = (0..n_f).map(|i| self.f.scope.var(i)).collect();
            let delta = Rc::new(Term::Delta { def: g, args });
            let ret_ty = self.ty(&f.ret, span)?;
            let sym = mk::apps(mk::global(self.p.g("eq::sym")), [(Rel::Rel, ret_ty.clone()), (Rel::Rel, app_here.clone()), (Rel::Rel, inner.clone()), (Rel::Rel, delta)]);
            let saved = self.f.scope.clone();
            let motive = (|| -> R<Tm> {
                self.push("z", Rel::Rel, &ret_ty, None)?;
                self.refines_goal_at(st, &mk::var(0), span)
            })();
            self.f.scope = saved;
            proof = Rc::new(Term::Transport { ty: ret_ty, lhs: inner, rhs: app_here, eq: sym, motive: motive?, val: proof });
        }
        Ok((proof, recursion))
    }

    /// The fact `f::refines ā` at a call of `f` with the arguments `all`
    /// (type and value arguments, then the `requires` proofs): `(lemma,
    /// type, proof)`, when `f::refines` was checked. Binders of the lemma
    /// beyond `f`'s own (a domain, a representation relation) stay in the
    /// fact's type (an implication the prover may instantiate).
    pub fn callee_refines(&mut self, id: ItemId, all: &[Tm]) -> Option<(GlobalId, Tm, Tm)> {
        let name = format!("{}::refines", self.krate.item(id).path);
        if !self.defs.iter().any(|d| d.name == name && d.status == DefStatus::Checked) {
            return None;
        }
        let rg = self.env.lookup_global(&name)?;
        let n = self.env.global_param_rels(rg)?.len().min(all.len());
        let args = &all[..n];
        let mut t = self.env.global_type(rg)?;
        for _ in 0..n {
            let next = match &*t {
                Term::Pi { cod, .. } => cod.clone(),
                _ => return None,
            };
            t = next;
        }
        // the statement's spec-side proofs are instantiated with the call's
        // arguments: re-certify their linear arithmetic
        let ty = super::recert::recertify(&self.env, &self.f.scope.ctx, &super::tm::subst_closed(&t, args));
        let proof = mk::apps(mk::global(rg), args.iter().map(|a| (Rel::Rel, a.clone())));
        Some((rg, ty, proof))
    }

    /// Before any item: a `#[refines(s)]` function `f` that `s` itself
    /// reaches (through spec functions and constants) is the vacuous
    /// refinement of DESIGN.md §15.1 (`#[spec] fn s(x) { f(x) }`); the
    /// dependency order would only report a cycle, so it is reported here as
    /// `error[spec-depends-on-impl]`.
    pub fn refines_cycle_check(&mut self) {
        if !self.s1.on {
            return;
        }
        let krate = self.krate;
        for it in &krate.items {
            let ItemKind::Fn(f) = &it.kind else { continue };
            let Some(r) = &f.spec.refines else { continue };
            // spec-side reachability from `s`
            let mut seen = std::collections::HashSet::new();
            let mut stack = vec![r.spec];
            let mut hit = false;
            while let Some(x) = stack.pop() {
                if !seen.insert(x) {
                    continue;
                }
                if x == it.id {
                    hit = true;
                    break;
                }
                let ghost_item = match &krate.item(x).kind {
                    ItemKind::Fn(g) => g.kind == crate::hir::FnKind::Spec,
                    ItemKind::Const(_) => krate.item(x).ghost,
                    _ => false,
                };
                // through spec items and the exec functions they call (whose
                // bodies may call `f`)
                let exec = matches!(&krate.item(x).kind, ItemKind::Fn(g) if g.kind == crate::hir::FnKind::Exec);
                if ghost_item || exec || x == r.spec {
                    stack.extend(super::order::refs(krate, x));
                }
            }
            if hit {
                let (sp, fp) = (krate.item(r.spec).path.to_string(), it.path.to_string());
                self.diag(
                    Diagnostic::error(DiagKind::SpecDependsOnImpl, r.span, format!("the specification `{sp}` of `#[refines]` on `{fp}` depends on `{fp}` itself"))
                        .note("a specification written in terms of the implementation it specifies is refined by every implementation: transcribe the reference semantics into `spec::` (DESIGN.md §15.1)"),
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // after all items
    // ------------------------------------------------------------------

    /// `#[refines]` on exec function `id`: after every item, the lemma was
    /// built (or its failure reported); nothing is left to do but make sure
    /// no annotation went unhandled (DESIGN.md §15.12: nothing is silently
    /// ignored).
    pub fn refines_hook(&mut self, id: ItemId, r: &Refines) {
        if !self.s1.on {
            return;
        }
        let handled = self.s1.refinements.iter().any(|x| x.item == id) || self.defs.iter().any(|d| d.item == Some(id) && !matches!(d.status, DefStatus::Checked));
        if !handled {
            let what = format!("`#[refines({})]` on `{}`", self.krate.item(r.spec).path, self.krate.item(id).path);
            self.diag(Diagnostic::error(DiagKind::Elab, r.span, format!("{what} was not elaborated (its function or its proof item did not reach the refinement stage)")));
        }
    }

    /// `#[proof(refines = f)]` item `id`: handled when the item was reached
    /// ([`Elab::refines_proof_item`]).
    pub fn refines_proof_hook(&mut self, _id: ItemId, _p: &ProofOf) {}

    /// `#[view(..)]` on type `id`: elaborated with the type
    /// ([`Elab::view_def`]).
    pub fn view_hook(&mut self, id: ItemId, v: &View) {
        if self.s1.on && !self.s1.views.contains_key(&id) && !self.diags.list.iter().any(|d| d.span == v.span()) {
            let what = format!("`#[view]` on `{}`", self.krate.item(id).path);
            self.diag(Diagnostic::error(DiagKind::Elab, v.span(), format!("{what} could not be elaborated")));
        }
    }

    /// The obligation and diagnostic records (and the failure flags) at
    /// this point, for a speculative attempt.
    pub(super) fn save_records(&self) -> Records {
        Records { obls: self.obligations.len(), diags: self.diags.list.len(), failed: self.f.failed, slots: self.f.slot_failures.as_ref().map(|v| v.len()) }
    }

    /// Every obligation recorded since `r` is proven.
    pub(super) fn records_proven_since(&self, r: &Records) -> bool {
        self.obligations[r.obls..].iter().all(|o| o.proven())
    }

    /// Takes the records made since `r` out (restored by
    /// [`Elab::restore_records`]).
    pub(super) fn split_records(&mut self, r: &Records) -> Taken {
        let obls = self.obligations.split_off(r.obls);
        let diags = self.diags.list.split_off(r.diags);
        let slots = match (self.f.slot_failures.as_mut(), r.slots) {
            (Some(v), Some(n)) => v.split_off(n),
            _ => vec![],
        };
        let failed = self.f.failed;
        self.f.failed = r.failed;
        Taken { obls, diags, slots, failed }
    }

    /// Drops the records made since `r` and puts `taken` back.
    pub(super) fn restore_records(&mut self, r: &Records, taken: Taken) {
        self.obligations.truncate(r.obls);
        self.diags.list.truncate(r.diags);
        if let (Some(v), Some(n)) = (self.f.slot_failures.as_mut(), r.slots) {
            v.truncate(n);
            v.extend(taken.slots);
        }
        self.obligations.extend(taken.obls);
        self.diags.list.extend(taken.diags);
        self.f.failed = taken.failed;
    }

    /// `#[represents(..)]` on struct `id`: elaborated with the type
    /// ([`Elab::represents_def`]); `S` must be `Abstract` (S2).
    pub fn represents_hook(&mut self, id: ItemId, r: &Represents) {
        if self.s1.on && !self.s1.represents.contains_key(&id) && !self.diags.list.iter().any(|d| d.span == r.span) {
            let what = format!("`#[represents]` on `{}`", self.krate.item(id).path);
            self.diag(Diagnostic::error(DiagKind::Elab, r.span, format!("{what} could not be elaborated")));
        }
    }

}


/// The records at a point of the elaboration ([`Elab::save_records`]).
pub(super) struct Records {
    obls: usize,
    diags: usize,
    failed: bool,
    slots: Option<usize>,
}

/// Records taken out by [`Elab::split_records`].
pub(super) struct Taken {
    pub(super) obls: Vec<super::ObligationRecord>,
    pub(super) diags: Vec<Diagnostic>,
    slots: Vec<(Span, ObligationKind, String)>,
    failed: bool,
}
