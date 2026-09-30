//! Ghost items and proof scripts (DESIGN.md §4.3–§4.5).
//!
//! * A lemma / law is the definition `Π(x : ⟦A⟧)..(h : ⟦P⟧).. ⟦Q⟧`
//!   (hypotheses **relevant**: lemma-like definitions are only used in
//!   irrelevant positions, §7.3). Its body is the proof built by its script;
//!   a law's script is its inline proof or the `#[proof]` item of the same
//!   name (whose parameters are identified with the law's). A law without a
//!   proof is an **open claim**: an error once verification is on (§4.5).
//! * Scripts are elaborated goal-directed ([`Elab::script`]); in lemma bodies
//!   facts and path equations are relevant binders (Mode::Proof):
//!
//! | step | elaboration |
//! | --- | --- |
//! | `assert(p)` | `let h : ⟦p⟧ = <prover>; …` |
//! | `assert(p, { steps })` | `let h : ⟦p⟧ = <steps>; …` |
//! | `lemma(args)`, `let h = lemma(args)` | `let h : Q[args] = lemma args <hyps by the prover>; …`; a call of the enclosing lemma is `rec` (induction hypothesis, measure-checked) |
//! | `match e { p => { steps } }` | dependent match; a variable scrutinee (inductive, tuple, slice) refines the goal and the hypotheses mentioning it ([`super::refine`]); another scrutinee generalizes its syntactic occurrences in the goal term (each arm's goal is the goal at the pattern), else keeps the goal; arms get the path equation |
//! | `if c { .. } else { .. }` | dependent bool match (same generalization) |
//! | `cases(k in a..b) { steps }` | range facts, then `k ≤ v` tests per value; each case rewrites the goal with `k = v` |
//! | `witness(e..)` | `pair(Σ.., e, <rest>)` against the `Exists` goal (behind spec functions: unfolded on the goal term) |
//! | `unfold(f)` | a transparent non-recursive `f`: its applications in the goal term are replaced by the instantiated body (conversion); otherwise `transport` along `delta(f; args)` for each application in the goal term (the body instantiated as a term, the rest of the goal folded); no application: the goal is unchanged (a warning) |
//! | `rewrite(h)`, `rewrite(a == b)`, `rewrite_rev(h)`, `rewrite(h, \|x\| p)` | `transport` with the motive generalizing the syntactic occurrences of the side in the goal term (else `abstract_occurrences` on the value, or the explicit motive); `a == b` is proven first |
//! | `exact(t)` | `t` (type-checked against the goal) |
//! | `bv()` | `bvrefl(T, a, b)` |
//! | `by_computation()` | `refl` when the goal's sides convert (no search; else a failure showing both evaluated sides), [`apply`] |
//! | `by_arithmetic()`, `by_unfolding(f, ..)` | the prover restricted to arithmetic and equality reasoning on a view of the goal whose functions are variables (the named definitions defined over them: a `let` of the body, or a defining equation used like `Delta`); the view's proof under `let`s binding the variables to the functions and the copied facts to the facts, [`closers`] |
//! | `by_contradiction()` | `absurd(goal, p)` with `p : Empty` proven from the facts alone, [`closers`] |
//! | `follows()` | the prover chain (unrestricted) |
//! | `apply(lemma)` | `lemma` applied to arguments inferred by first-order matching of its `requires` against the facts (and its `ensures` against the goal), [`apply`] |
//! | `calc! { e0 == e1 by {..}; == e2; .. }` | each link proven; `==` chains by transport (transitivity), `<=`/`<` chains by the prover over the links; last statement: must be the goal, else a fact, [`apply`] |
//! | `let x = e` | ghost `let` |
//! | `show()` | a warning with the goal and facts |
//! | `todo()` | an open obligation (the build fails) |
//!
//! **Goal terms.** Steps keep the goal as a term and transform it by
//! substitution ([`super::tm::abstract_syntactic`],
//! [`super::tm::unfold_syntactic`], [`super::tm::simp_redexes`]): a goal
//! about a large transparent function (a verifier's entry point) has a huge
//! *value* — evaluation unfolds every transparent callee — and quoting it
//! back (to build a motive or the next goal) is impractical, while its term
//! keeps the calls folded. The kernel checks every step by conversion.
//!
//! At the end of a block without a closing statement the prover must close
//! the goal: after other statements ([`Elab::close_implicit`]) that warns
//! unless the goal is closed by conversion or by a fact in scope (an empty
//! block, or the cases of a trailing `by_cases`, are handled by typeck's
//! warnings and by `by_cases` itself).
//! `proof! { .. }` blocks in exec code run the non-terminal steps in the
//! current (exec) context: their facts are irrelevant binders for later
//! obligations.

use std::rc::Rc;

use sandblaster_kernel::term::{DefKind, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::{mk, shift};
use sandblaster_kernel::value::{EnvEntry, VEnv, Value};

use super::exec::Answer;
use super::obl::TRY_BUDGET;
use super::items::{lam_tele, pi_tele};
use super::{internal, unsupported, DefStatus, Elab, ElabError, ErrKind, FnState, ItemGlobal, LawRecord, Mode, Val, R};
use crate::diag::{DiagKind, Diagnostic};
use crate::hir::*;
use crate::prover::{FactOrigin, ObligationKind};
use crate::span::Span;

// `apply(lemma)` argument inference, `by_computation()`, `calc!`
#[path = "apply.rs"]
mod apply;

// `by_arithmetic()`, `by_unfolding(..)`, `by_contradiction()`
#[path = "closers.rs"]
mod closers;

impl<'a> Elab<'a> {
    // ------------------------------------------------------------------
    // items
    // ------------------------------------------------------------------

    /// `#[lemma] fn`.
    pub fn lemma_item(&mut self, id: ItemId, f: &'a FnDef) -> R<()> {
        let it = self.krate.item(id);
        // a prelude lemma (`sandblaster::lemmas::..`, DESIGN.md §4.5): the
        // kernel lemma, loaded (and checked) with the lemma files
        if let Some(kname) = crate::resolve::prelude_lemma_kernel_name(&it.path) {
            let g = self.env.lookup_global(&kname).ok_or_else(|| ElabError { span: it.span, msg: format!("prelude lemma `{kname}` is not loaded"), kind: ErrKind::Internal })?;
            self.globals.insert(id, ItemGlobal::Def(g));
            return Ok(());
        }
        let name = it.path.to_string();
        let FnBody::Script(steps) = &f.body else { return internal(it.span, "lemma without a script") };
        let g = self.ghost_def(id, f, f, steps, &name, DefKind::Lemma, it.span)?;
        self.globals.insert(id, ItemGlobal::Def(g));
        // a lemma of a `#[bridges]` module, checked: a rule of `auto` (an
        // unconditional equation rewrites, a conditional one is backward)
        if self.krate.in_bridges_module(id) && self.defs.iter().rev().find(|d| d.name == name).is_some_and(|d| d.status == DefStatus::Checked) {
            // unconditional: every binder of its statement is a value (no
            // hypothesis, no type parameter)
            let mut t = self.env.global_type(g);
            let mut plain = true;
            while let Some(ty) = t.clone() {
                let sandblaster_kernel::term::Term::Pi { dom, cod, .. } = &*ty else { break };
                if matches!(&**dom, sandblaster_kernel::term::Term::Eq { .. } | sandblaster_kernel::term::Term::Sort(_)) {
                    plain = false;
                }
                t = Some(cod.clone());
            }
            // an inequality (`holds(a <= b)`), or a conditional equation of
            // integers: a linarith rule (instances join the linear problems
            // whose atoms match it; its hypotheses, if any, are subgoals)
            let inequality = t.as_ref().is_some_and(|c| {
                matches!(&**c, sandblaster_kernel::term::Term::Eq { lhs, .. }
                    if matches!(&**lhs, sandblaster_kernel::term::Term::Prim { op: sandblaster_kernel::term::PrimOp::Le(_) | sandblaster_kernel::term::PrimOp::Lt(_) | sandblaster_kernel::term::PrimOp::Ge(_) | sandblaster_kernel::term::PrimOp::Gt(_), .. }))
            });
            let int_equation = t.as_ref().is_some_and(|c| matches!(&**c, sandblaster_kernel::term::Term::Eq { ty, .. } if matches!(&**ty, sandblaster_kernel::term::Term::IntTy(sandblaster_kernel::term::Width::Int))));
            // a test's outcome read as another test's (`requires(t(a) ==
            // false); ensures(u(a) == false)`): a forward rule, triggered by
            // the fact the first test leaves (an arithmetic comparison as
            // the first hypothesis, `requires(x >= 0)`, is a side condition
            // linear arithmetic discharges: such a lemma stays a linarith
            // rule below)
            let comparison = |c: &sandblaster_kernel::term::Tm| {
                matches!(&**c, sandblaster_kernel::term::Term::Eq { lhs, .. }
                    if matches!(&**lhs, sandblaster_kernel::term::Term::Prim { op: sandblaster_kernel::term::PrimOp::Le(_) | sandblaster_kernel::term::PrimOp::Lt(_) | sandblaster_kernel::term::PrimOp::Ge(_) | sandblaster_kernel::term::PrimOp::Gt(_), .. }))
            };
            let bool_lit = |c: &sandblaster_kernel::term::Tm| matches!(&**c, sandblaster_kernel::term::Term::Eq { rhs, .. } if matches!(&**rhs, sandblaster_kernel::term::Term::Ctor { args, .. } if args.is_empty()));
            let first_hyp_test = {
                let mut t2 = self.env.global_type(g);
                let mut found = None;
                while let Some(ty) = t2.clone() {
                    let sandblaster_kernel::term::Term::Pi { dom, cod, .. } = &*ty else { break };
                    if matches!(&**dom, sandblaster_kernel::term::Term::Eq { .. }) {
                        found = Some(bool_lit(dom) && !comparison(dom));
                        break;
                    }
                    t2 = Some(cod.clone());
                }
                found.unwrap_or(false)
            };
            if !plain && first_hyp_test && t.as_ref().is_some_and(bool_lit) {
                crate::auto::lemmas::register_bridge_role(&name, crate::auto::lemmas::Role::Forward);
            } else if inequality || (!plain && int_equation) {
                crate::auto::lemmas::register_bridge_role(&name, crate::auto::lemmas::Role::Linarith);
            } else {
                crate::auto::lemmas::register_bridge(&name, plain);
            }
        }
        Ok(())
    }

    /// `#[law] fn` with its proof.
    pub fn law_item(&mut self, id: ItemId, f: &'a FnDef) -> R<()> {
        let it = self.krate.item(id);
        let name = it.path.to_string();
        let lp = f.law_proof.unwrap_or(LawProof::Missing);
        let (proof_fn, steps, proof_name) = match lp {
            LawProof::Missing => {
                self.diags.push(Diagnostic::error(DiagKind::Obligation, it.span, format!("law `{}` is an open claim (no proof)", it.path)).note("write the `#[proof]` item of the same name in PROOF.rs, or an inline proof (DESIGN.md §4.5)"));
                self.laws.push(LawRecord { item: id, name: name.clone(), proof: "missing".into(), status: DefStatus::Open });
                self.defs.push(super::DefRecord { name: name.clone(), kind: DefKind::Law, item: Some(id), global: None, status: DefStatus::Open, span: it.span });
                self.globals.insert(id, ItemGlobal::Failed("is an open claim".into()));
                return Ok(());
            }
            LawProof::Inline => match &f.body {
                FnBody::Script(s) => (f, s, "inline".to_string()),
                _ => return internal(it.span, "inline law without script"),
            },
            LawProof::Item(p) => {
                let pf = self.krate.fn_def(p).ok_or_else(|| ElabError { span: it.span, msg: "proof item is not a function".into(), kind: ErrKind::Internal })?;
                match &pf.body {
                    FnBody::Script(s) => (pf, s, self.krate.item(p).path.to_string()),
                    _ => return internal(it.span, "proof item without script"),
                }
            }
        };
        let r = self.ghost_def(id, f, proof_fn, steps, &name, DefKind::Law, it.span);
        let status = match (&r, self.defs.last().map(|d| &d.status)) {
            (Ok(_), Some(DefStatus::Checked)) => DefStatus::Checked,
            // proven against a stand-in body: not proven
            (Ok(_), Some(DefStatus::Blocked(m))) => DefStatus::Blocked(m.clone()),
            (Ok(_), _) => DefStatus::Unproven,
            (Err(e), _) => DefStatus::Blocked(e.msg.clone()),
        };
        self.laws.push(LawRecord { item: id, name, proof: proof_name, status });
        let g = r?;
        self.globals.insert(id, ItemGlobal::Def(g));
        Ok(())
    }

    /// Builds a lemma/law definition: the contract comes from `f` (the law
    /// or lemma), the script and its locals from `pf` (the same item, or the
    /// `#[proof]` item whose parameters are identified with `f`'s).
    #[allow(clippy::too_many_arguments)]
    fn ghost_def(&mut self, id: ItemId, f: &'a FnDef, pf: &'a FnDef, steps: &'a [ScriptStmt], name: &str, kind: DefKind, span: Span) -> R<sandblaster_kernel::term::GlobalId> {
        self.f = FnState::new(name.to_string(), Some(id), &f.locals, span);
        self.f.fdef = Some(f);
        self.f.mode = Mode::Proof;
        let (mut binders, pending) = self.fn_params(f, span)?;
        self.fn_requires(f, &mut binders, Rel::Rel)?;
        let arity = self.depth();
        let goal = match &f.ensures {
            Some(en) => self.prop(&en.prop)?,
            None => mk::ind(self.p.unit, vec![]),
        };
        let ty = pi_tele(&binders, goal.clone());
        // the proof item's parameters are the law's
        if !std::ptr::eq(f, pf) {
            self.f.locals = &pf.locals;
            for (i, p) in pf.params.iter().enumerate() {
                if let PatKind::Binding { local, .. } = &p.pat.kind {
                    let lvl = f.generics.len() as u32 + i as u32;
                    self.f.scope.locals.insert(*local, lvl);
                }
            }
        }
        // recursion (induction through recursive applications)
        let rec_item = if std::ptr::eq(f, pf) { id } else { self.krate.items.iter().find(|x| matches!(&x.kind, ItemKind::Fn(g) if std::ptr::eq(g, pf))).map(|x| x.id).unwrap_or(id) };
        let recursion = if script_recursive(steps, rec_item) {
            match self.script_measure(pf, steps, rec_item) {
                Some((m, w)) => {
                    self.f.rec = Some(super::RecInfo { item: Some(rec_item), ty: ty.clone(), arity, measure: Some((m.clone(), w)) });
                    sandblaster_kernel::term::Recursion::Measure { measure: m }
                }
                None => return unsupported(span, "cannot infer a measure for this induction; add `#[decreases(e)]`"),
            }
        } else {
            sandblaster_kernel::term::Recursion::None
        };
        let gv = Val::new(goal, arity);
        // parameters of invariant types have their invariant as a
        // hypothesis (DESIGN.md §15.3: laws and lemmas quantifying over an
        // invariant type gain it)
        let body = self.param_inv_facts(f, 0, span, &mut |s| {
            s.bind_params(&pending, 0, span, &mut |s| {
                let g = gv.clone();
                let k = if kind == DefKind::Law { ObligationKind::LawGoal } else { ObligationKind::Ensures };
                s.script(steps, g, k, span)
            })
        })?;
        let lam = lam_tele(&binders, body);
        let failed = self.f.failed;
        self.add_definition(name, kind, Some(id), ty, lam, recursion, arity, false, failed, span)
    }

    /// The proof of `f::refines` by the script of the `#[proof(refines =
    /// f)]` item `pid` (DESIGN.md §15.2): the telescope of the lemma is in
    /// scope; the proof item's parameters are identified with `f`'s (like
    /// a law's `#[proof]`), and its recursive applications are induction
    /// hypotheses (measure recursion). Returns the proof and the recursion.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn refines_script(&mut self, pid: ItemId, pf: &'a FnDef, f: &'a FnDef, steps: &'a [ScriptStmt], pending: &[(u32, &'a Pat)], goal: Tm, ty: &Tm, arity: u32, span: Span) -> R<(Tm, sandblaster_kernel::term::Recursion)> {
        self.f.locals = &pf.locals;
        for (i, p) in pf.params.iter().enumerate() {
            if let PatKind::Binding { local, .. } = &p.pat.kind {
                // `f`'s `#[ghost]` parameters (the last ones) are projections
                // of its ghost bundle (§15.3)
                if let Some(PatKind::Binding { local: fl, .. }) = f.params.get(i).filter(|q| q.ghost).map(|q| &q.pat.kind) {
                    if let Some(v) = self.f.scope.ghost_locals.get(fl).cloned() {
                        self.f.scope.ghost_locals.insert(*local, v);
                    }
                    continue;
                }
                let lvl = f.generics.len() as u32 + i as u32;
                self.f.scope.locals.insert(*local, lvl);
            }
        }
        let recursion = if script_recursive(steps, pid) {
            match self.script_measure(pf, steps, pid) {
                Some((m, w)) => {
                    self.f.rec = Some(super::RecInfo { item: Some(pid), ty: ty.clone(), arity, measure: Some((m.clone(), w)) });
                    sandblaster_kernel::term::Recursion::Measure { measure: m }
                }
                None => return unsupported(span, "cannot infer a measure for this induction; add `#[decreases(e)]`"),
            }
        } else {
            sandblaster_kernel::term::Recursion::None
        };
        let gv = Val::new(goal, arity);
        let body = self.param_inv_facts(f, 0, span, &mut |s| s.bind_params(pending, 0, span, &mut |s| s.script(steps, gv.clone(), ObligationKind::Refines, span)))?;
        Ok((body, recursion))
    }

    fn script_measure(&mut self, pf: &'a FnDef, steps: &'a [ScriptStmt], rec_item: ItemId) -> Option<(Tm, Width)> {
        // `#[decreases(e)]`: the measure is `e` (its decrease is an
        // obligation at every induction hypothesis)
        if let Some(dec) = &pf.decreases {
            let m = self.pure_expr(&dec.measure).ok()?;
            let w = self.width_of(&dec.measure.ty, dec.measure.span).ok()?;
            return Some((m, w));
        }
        // uint parameter passed as `p − k`, or slice parameter passed as a rest binding
        let mut calls: Vec<&'a [Expr]> = Vec::new();
        collect_apps(steps, rec_item, &mut calls);
        // induction on the fields of a recursive spec type (SEMANTICS.md §13.9)
        if let Some(m) = self.size_measure(&pf.params, pf.generics.len(), &calls, &super::recursive::script_field_bindings(steps, &|t| matches!(t.peel_refs(), Ty::Adt(id, _) if self.krate.is_recursive_adt(*id)))) {
            return Some(m);
        }
        let mut rest_of = std::collections::HashMap::new();
        collect_script_rest(steps, &mut rest_of);
        for (j, p) in pf.params.iter().enumerate() {
            let PatKind::Binding { local, sub: None, .. } = &p.pat.kind else { continue };
            let lvl = pf.generics.len() as u32 + j as u32;
            let ok = !calls.is_empty()
                && calls.iter().all(|args| {
                    let Some(a) = args.get(j) else { return false };
                    let a = Elab::peel(a);
                    match (p.ty.peel_refs(), &a.kind) {
                        (Ty::Uint(_) | Ty::Nat, ExprKind::Binary(BinOp::Sub, x, y)) => matches!(&Elab::peel(x).kind, ExprKind::Local(l) if l == local) && matches!(&y.kind, ExprKind::Lit(Lit::Int(k)) if *k >= 1),
                        (Ty::Slice(_) | Ty::Seq(_), ExprKind::Local(t)) => rest_of.get(t) == Some(local),
                        _ => false,
                    }
                });
            if ok {
                let var = self.f.scope.var(lvl);
                return match p.ty.peel_refs() {
                    Ty::Uint(u) => Some((var, u.width())),
                    Ty::Nat => Some((var, Width::Int)),
                    Ty::Slice(_) => Some((mk::fst(var), Width::Usize)),
                    Ty::Seq(e) => {
                        let et = self.ty(e, p.span).ok()?;
                        Some((mk::apps(mk::global(self.p.g("seq::len")), [(Rel::Rel, et), (Rel::Rel, var)]), Width::Int))
                    }
                    _ => None,
                };
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // exec proof blocks
    // ------------------------------------------------------------------

    /// `proof! { steps }` inside exec code: the non-terminal steps, whose
    /// facts are available to later obligations.
    pub fn exec_proof(&mut self, steps: &'a [ScriptStmt], span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        self.exec_steps(steps, 0, span, k)
    }

    fn exec_steps(&mut self, steps: &'a [ScriptStmt], i: usize, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let Some(st) = steps.get(i) else { return k(self) };
        let sp = st.span;
        match &st.kind {
            ScriptKind::Assert { prop, steps: sub } => {
                let p = self.prop(prop)?;
                let pf = match sub {
                    None => self.prove(ObligationKind::Assert, sp, &p, false)?,
                    Some(sub) => {
                        let saved = self.f.mode;
                        let r = self.script(sub, Val::new(p.clone(), self.depth()), ObligationKind::Assert, sp);
                        self.f.mode = saved;
                        r?
                    }
                };
                self.fact_in("h_assert", p, pf, FactOrigin::Assert, sp, &mut |s| s.exec_steps(steps, i + 1, span, k))
            }
            ScriptKind::Apply { binder, app, infer, .. } => {
                let binder = *binder;
                let mut rest = |s: &mut Elab<'a>, pf: Tm, ty: Tm| {
                    s.fact_in("h_lemma", ty, pf, FactOrigin::Assert, sp, &mut |s| {
                        if let Some(b) = binder {
                            let lvl = s.depth() - 1;
                            s.f.scope.locals.insert(b, lvl);
                        }
                        s.exec_steps(steps, i + 1, span, k)
                    })
                };
                if *infer {
                    let (pf, ty) = self.apply_infer(app, None, false)?;
                    rest(self, pf, ty)
                } else {
                    self.lemma_app_k(app, false, &mut rest)
                }
            }
            ScriptKind::Step { call } => self.step_fact(call, sp, &mut |s, pf, ty| s.fact_in("h_step", ty, pf, FactOrigin::Assert, sp, &mut |s| s.exec_steps(steps, i + 1, span, k))),
            ScriptKind::Let { pat, value } => self.expr(value, &mut |s, v| s.bind_irrefutable(pat, v, sp, &mut |s| s.exec_steps(steps, i + 1, span, k))),
            ScriptKind::Show => {
                self.show_goal(None, sp);
                self.exec_steps(steps, i + 1, span, k)
            }
            ScriptKind::Calc { links, concl, rel, .. } => self.calc_chain(links, concl, *rel, sp, &mut |s, c, pf| s.fact_in("h_calc", c, pf, FactOrigin::Assert, sp, &mut |s| s.exec_steps(steps, i + 1, span, k))),
            _ => unsupported(sp, "only `assert`, lemma applications (`apply`), `calc!`, `let` and `show` are allowed in `proof!` blocks of exec code"),
        }
    }

    // ------------------------------------------------------------------
    // scripts
    // ------------------------------------------------------------------

    /// Proves `goal` (a type term) with `steps`; the prover closes what is
    /// left (§4.4).
    pub fn script(&mut self, steps: &'a [ScriptStmt], goal: Val, kind: ObligationKind, span: Span) -> R<Tm> {
        let relevant = self.f.mode == Mode::Proof;
        let Some((st, rest)) = steps.split_first() else {
            let g = goal.at(self.depth());
            return self.prove(kind, span, &g, relevant);
        };
        let sp = st.span;
        match &st.kind {
            ScriptKind::Assert { prop, steps: sub } => {
                let p = self.prop(prop)?;
                let pf = match sub {
                    None => self.prove(ObligationKind::Assert, sp, &p, relevant)?,
                    Some(sub) => self.script(sub, Val::new(p.clone(), self.depth()), ObligationKind::Assert, sp)?,
                };
                self.fact_in("h_assert", p, pf, FactOrigin::Assert, sp, &mut |s| s.script_rest(rest, goal.clone(), kind.clone(), span, sp))
            }
            ScriptKind::Apply { app, optional: true, .. } => {
                // an induction hypothesis of `by_induction(..)`: attempted,
                // kept only when every hypothesis of the lemma is proven
                match self.try_lemma_app(app, relevant)? {
                    Some((pf, ty)) => self.fact_in("h_ih", ty, pf, FactOrigin::Assert, sp, &mut |s| s.script_rest(rest, goal.clone(), kind.clone(), span, sp)),
                    None => self.script_rest(rest, goal, kind, span, sp),
                }
            }
            ScriptKind::Apply { binder, app, infer, .. } => {
                let binder = *binder;
                let origin = FactOrigin::Assert;
                let mut then = |s: &mut Elab<'a>, pf: Tm, ty: Tm| {
                    s.fact_in("h_lemma", ty, pf, origin.clone(), sp, &mut |s| {
                        if let Some(b) = binder {
                            let lvl = s.depth() - 1;
                            s.f.scope.locals.insert(b, lvl);
                        }
                        s.script_rest(rest, goal.clone(), kind.clone(), span, sp)
                    })
                };
                if *infer {
                    let (pf, ty) = self.apply_infer(app, Some(&goal), relevant)?;
                    then(self, pf, ty)
                } else {
                    self.lemma_app_k(app, relevant, &mut then)
                }
            }
            ScriptKind::Step { call } => self.step_fact(call, sp, &mut |s, pf, ty| s.fact_in("h_step", ty, pf, FactOrigin::Assert, sp, &mut |s| s.script_rest(rest, goal.clone(), kind.clone(), span, sp))),
            ScriptKind::Let { pat, value } => self.expr(value, &mut |s, v| s.bind_irrefutable(pat, v, sp, &mut |s| s.script_rest(rest, goal.clone(), kind.clone(), span, sp))),
            ScriptKind::Show => {
                self.show_goal(Some(&goal), sp);
                self.script_rest(rest, goal, kind, span, sp)
            }
            ScriptKind::Using(ids) => self.using_facts(ids, 0, rest, goal, kind, span, sp),
            ScriptKind::Todo => {
                let g = goal.at(self.depth());
                self.todo_obligation(sp, &g);
                Ok(Rc::new(Term::Erased))
            }
            ScriptKind::Exact(t) => {
                let (pf, ty) = self.proof_term(t, relevant)?;
                let g = goal.at(self.depth());
                let gv = self.eval(&g)?;
                let tv = self.eval(&ty)?;
                let mut b = self.budget();
                if !self.env.conv(sandblaster_kernel::term::Lvl(self.depth()), &gv, &tv, &mut b).unwrap_or(false) {
                    let id = self.obligations.len() as u32;
                    let failure = crate::prover::AutoFailure { tried: vec![format!("`exact` term has type {}", self.show_tm(&ty))], ..Default::default() };
                    self.fail_obligation(id, kind, sp, &g, failure, true);
                    return Ok(Rc::new(Term::Erased));
                }
                let id = self.obligations.len() as u32;
                self.record(id, kind, sp, super::OblStatus::Proven { by: "script".into() }, true, String::new());
                Ok(pf)
            }
            ScriptKind::Bv => {
                let g = goal.at(self.depth());
                // the goal's own sides when it is written as an equation
                // (quoting its value can leave `Erased` in irrelevant
                // positions, e.g. of eta-expanded array variables, which
                // `BvRefl` does not accept); else the evaluated sides
                let t = match &*g {
                    Term::Eq { ty, lhs, rhs } if !super::tm::has_erased(lhs) && !super::tm::has_erased(rhs) => Rc::new(Term::BvRefl { ty: ty.clone(), lhs: lhs.clone(), rhs: rhs.clone() }),
                    _ => {
                        let gv = self.eval(&g)?;
                        let Value::Eq { ty, lhs, rhs } = &*gv else { return unsupported(sp, "`bv()` needs an equation goal") };
                        Rc::new(Term::BvRefl { ty: self.quote(ty, None), lhs: self.quote(lhs, None), rhs: self.quote(rhs, None) })
                    }
                };
                let id = self.obligations.len() as u32;
                // decided now (the kernel's word normalizer), so a false
                // equation is an unproven obligation with both normal forms,
                // not a kernel rejection of the whole definition
                if let Err(e) = self.check_proof(&t, &g, relevant) {
                    // a shift by a variable amount, `/`, `%` or `pow2` in `Int`
                    // (pe P3/C3): outside word algebra; linear arithmetic with the
                    // shift facts (`bits::shr_is_div_pow2_<w>`) decides them, with
                    // only the facts that bound the shift amounts
                    // ([`Elab::by_bv_arithmetic`]): still a word identity
                    if super::tm::any_node(&g, &mut |n| match n {
                        Term::Prim { op: PrimOp::Shr(_) | PrimOp::WShr(_) | PrimOp::Shl(_) | PrimOp::WShl(_), args, .. } => !matches!(&*args[1], Term::Lit { .. }),
                        Term::Prim { op: PrimOp::IDiv | PrimOp::IMod, .. } => true,
                        _ => false,
                    }) {
                        return self.by_bv_arithmetic(goal, kind, sp);
                    }
                    // an array or list result: the first element whose sides
                    // differ modulo word algebra (the whole normal forms are
                    // long and share their prefix)
                    let msg = match self.bv_first_difference(&g) {
                        Some(m) => m,
                        None => e.chars().take(1500).collect::<String>(),
                    };
                    let failure = crate::prover::AutoFailure { tried: vec![format!("`bv()`: {msg}")], ..Default::default() };
                    self.fail_obligation(id, kind, sp, &g, failure, true);
                    return Ok(Rc::new(Term::Erased));
                }
                self.record(id, kind, sp, super::OblStatus::Proven { by: "script(bv)".into() }, true, String::new());
                Ok(t)
            }
            ScriptKind::Witness(es) => self.witness(es, 0, rest, goal, kind, span, sp),
            ScriptKind::UseHyp { index, args } => {
                let name = format!("h{index}");
                let Some(lvl) = self.f.scope.facts.iter().rev().map(|f| f.lvl.0).find(|l| self.f.scope.ctx.entries.get(*l as usize).is_some_and(|e| &*e.name == name.as_str())) else {
                    return unsupported(sp, format!("`use_hyp({index}, ..)`: no hypothesis `{name}` in scope (it names a hypothesis of the statement of a `#[proof(complete = ..)]` item)"));
                };
                let Some(ty_t) = self.f.scope.fact_tys.get(&lvl).cloned() else { return internal(sp, "use_hyp: the hypothesis has no type term") };
                let d = self.depth();
                let head = self.f.scope.var(lvl);
                let ty_now = shift(&ty_t, (d - lvl) as i64);
                self.use_hyp_args(head, ty_now, args, 0, rest, goal, kind, span, sp)
            }
            ScriptKind::Unfold(target) => {
                let g = match target {
                    UnfoldTarget::Item(id) => self.item_global(*id, sp)?,
                    UnfoldTarget::Builtin(b) => {
                        let n = match b {
                            crate::builtins::Builtin::Int(m, w) => format!("{}::{}", w.name(), m.name()),
                            _ => return unsupported(sp, "`unfold` of this builtin"),
                        };
                        self.env.lookup_global(&n).ok_or_else(|| ElabError { span: sp, msg: format!("no prelude definition `{n}`"), kind: ErrKind::Unsupported })?
                    }
                    UnfoldTarget::Ghost(g) => {
                        let n = g.nat_def().unwrap_or_default();
                        self.env.lookup_global(n).ok_or_else(|| ElabError { span: sp, msg: format!("no ghost-library definition `{n}`"), kind: ErrKind::Unsupported })?
                    }
                };
                self.unfold_goal(g, goal, rest, kind, span, sp, 0, 0)
            }
            ScriptKind::Rewrite { eq, rev, motive } => self.rewrite_step(eq, *rev, motive.as_ref(), rest, goal, kind, span, sp),
            ScriptKind::Match { scrut, arms } => self.script_match(scrut, arms, goal, kind, span, sp),
            ScriptKind::If { cond, then, els } => self.script_if(cond, then, els, goal, kind, span, sp),
            ScriptKind::Cases { var, lo, hi, inclusive, steps: body } => self.cases(*var, lo, hi, *inclusive, body, goal, kind, span, sp),
            ScriptKind::Follows => {
                let g = goal.at(self.depth());
                self.prove(kind, sp, &g, relevant)
            }
            ScriptKind::Compute => self.by_computation(goal, kind, sp),
            ScriptKind::Lockstep => {
                let g = goal.at(self.depth());
                match self.by_lockstep(&g, sp)? {
                    Some(p) => Ok(p),
                    None => {
                        // the prover on the whole goal; if it fails too, the
                        // lockstep's report is a note of the failure
                        let report = super::lockstep::take_failure();
                        let nd = self.diags.list.len();
                        let p = self.prove(kind, sp, &g, relevant)?;
                        if let Some(r) = report
                            && self.diags.list.len() > nd
                            && let Some(d) = self.diags.list.last_mut()
                        {
                            d.notes.push((None, r));
                        }
                        Ok(p)
                    }
                }
            }
            ScriptKind::Arithmetic => self.by_reasoning(goal, kind, sp, &[]),
            ScriptKind::Unfolding(names) => self.by_reasoning(goal, kind, sp, names),
            ScriptKind::Contradiction => self.by_contradiction(goal, kind, sp),
            ScriptKind::Calc { links, concl, rel, goal: closes } => {
                // last statement: the chain proves the goal; else a fact
                let closes = *closes;
                self.calc_chain(links, concl, *rel, sp, &mut |s, c, pf| {
                    if closes {
                        s.calc_close(&goal, &c, pf, kind.clone(), sp)
                    } else {
                        s.fact_in("h_calc", c, pf, FactOrigin::Assert, sp, &mut |s| s.script_rest(rest, goal.clone(), kind.clone(), span, sp))
                    }
                })
            }
        }
    }

    /// The rest of a block after the statement at `last`: the next
    /// statements, or the end of the block ([`Elab::close_implicit`]).
    fn script_rest(&mut self, rest: &'a [ScriptStmt], goal: Val, kind: ObligationKind, span: Span, last: Span) -> R<Tm> {
        if rest.is_empty() {
            return self.close_implicit(goal, kind, span, last, OpenEnd::Block);
        }
        self.script(rest, goal, kind, span)
    }

    /// A goal left without a closing statement (a block that ends after
    /// the statement at `at`, or a `calc!` link without `by`): the prover
    /// closes it, and a warning asks for a closing statement unless the
    /// goal is closed by conversion or by a fact in scope (every close must
    /// say why it holds, docs/PROOF-GUIDE.md).
    pub(super) fn close_implicit(&mut self, goal: Val, kind: ObligationKind, span: Span, at: Span, what: OpenEnd) -> R<Tm> {
        let relevant = self.f.mode == Mode::Proof;
        let g = goal.at(self.depth());
        let n = self.obligations.len();
        let pf = self.prove(kind, span, &g, relevant)?;
        let proven = self.obligations.get(n).is_some_and(|o| o.proven());
        if proven && !self.closed_directly(&g) {
            let (msg, note) = match what {
                OpenEnd::Block => ("the block ends without a closing statement: the automation must close the goal by itself", "write `follows();` to say so, or a closing statement that says why the goal holds"),
                OpenEnd::CalcLink => ("`calc!` link without `by`: the automation must prove it by itself", "write `by { follows(); }` to say so, or `by { .. }` with a closing statement that says why the link holds"),
            };
            // once per statement (the cases of a `by_cases` share it)
            if !self.diags.list.iter().any(|dg| dg.span == at && dg.msg == msg) {
                self.diags.push(Diagnostic::warning(DiagKind::Script, at, msg).note(note).note(crate::typeck::script::CLOSERS_NOTE));
            }
        }
        Ok(pf)
    }

    /// Whether a goal (a term at the current depth) is closed by conversion
    /// (`a == a` after evaluation, `()`) or by a fact in scope (or a
    /// component of a conjunction fact), componentwise for a conjunction.
    fn closed_directly(&self, g: &Tm) -> bool {
        let Ok(gv) = self.eval(g) else { return false };
        self.closed_directly_v(&gv, self.depth(), 2)
    }

    /// A small budget for the conversions of [`Elab::closed_directly`]: it
    /// only decides whether to warn (running out means "warn").
    fn warn_budget(&self) -> sandblaster_kernel::value::Budget {
        sandblaster_kernel::value::Budget { steps: self.opts.goal_budget.min(2_000_000) }
    }

    fn closed_directly_v(&self, gv: &sandblaster_kernel::value::V, d: u32, fuel: u32) -> bool {
        let lv = sandblaster_kernel::term::Lvl(d);
        match &**gv {
            Value::Eq { lhs, rhs, .. } => {
                let mut b = self.warn_budget();
                if self.env.conv(lv, lhs, rhs, &mut b).unwrap_or(false) {
                    return true;
                }
            }
            Value::Ind { ind, .. } if *ind == self.p.unit => return true,
            _ => {}
        }
        for fr in &self.f.scope.facts {
            if self.f.scope.hidden.contains(&fr.lvl.0) {
                continue;
            }
            let Some(e) = self.f.scope.ctx.entries.get(fr.lvl.0 as usize) else { continue };
            if self.fact_matches(&e.ty, gv, d, 2) {
                return true;
            }
        }
        if fuel > 0
            && let Value::Sigma { fst, snd, .. } = &**gv
        {
            return self.closed_directly_v(fst, d, fuel - 1) && self.instantiate_fresh(snd, fst, d).is_some_and(|v| self.closed_directly_v(&v, d + 1, fuel - 1));
        }
        false
    }

    /// Whether a fact's type (or a component of it, for a conjunction) is
    /// the goal `gv` (at depth `d`).
    fn fact_matches(&self, fty: &sandblaster_kernel::value::V, gv: &sandblaster_kernel::value::V, d: u32, fuel: u32) -> bool {
        let mut b = self.warn_budget();
        if self.env.conv(sandblaster_kernel::term::Lvl(d), fty, gv, &mut b).unwrap_or(false) {
            return true;
        }
        if fuel > 0
            && let Value::Sigma { fst, snd, .. } = &**fty
        {
            return self.fact_matches(fst, gv, d, fuel - 1) || self.instantiate_fresh(snd, fst, d).is_some_and(|v| self.fact_matches(&v, gv, d + 1, fuel - 1));
        }
        false
    }

    /// A Σ's second component instantiated with a fresh variable (level
    /// `d`) of the first component's type.
    fn instantiate_fresh(&self, snd: &sandblaster_kernel::value::Closure, fst: &sandblaster_kernel::value::V, d: u32) -> Option<sandblaster_kernel::value::V> {
        let x = self.env.fresh_var(sandblaster_kernel::term::Lvl(d), Rel::Rel, fst);
        let mut env = (*snd.env.0).clone();
        env.push(x);
        let mut b = self.warn_budget();
        self.env.eval(&VEnv(Rc::new(env)), sandblaster_kernel::term::Lvl(d + 1), &snd.body, &mut b).ok()
    }

    /// A warning with the goal and the facts (`show()`, §4.4).
    fn show_goal(&mut self, goal: Option<&Val>, sp: Span) {
        let mut text = String::new();
        if let Some(g) = goal {
            text.push_str(&format!("goal: {}", self.show_tm(&g.at(self.depth()))));
        }
        for fr in self.f.scope.facts.clone() {
            if let Some(e) = self.f.scope.ctx.entries.get(fr.lvl.0 as usize) {
                let shown = super::show::value(&self.env, &self.f.scope.names(), &e.ty, 600);
                text.push_str(&format!("\n  fact {}: {shown}", e.name));
            }
        }
        let mut d = Diagnostic::warning(DiagKind::Script, sp, "show()");
        d.goal = Some(text);
        self.diags.push(d);
    }

    /// `f::step(args)`: the one-step unfolding of `f` at `args` — the fact
    /// `f(args) == body[args]`, where the body keeps its recursive calls as
    /// calls of `f` — proven by `delta(f; args)`, which the kernel checks
    /// (so a wrong statement is rejected). `k` gets the proof and the
    /// statement at the depth after the call's arguments (an exec call's
    /// `requires` are proven as usual, its facts stay in scope).
    fn step_fact(&mut self, call: &'a Expr, sp: Span, k: &mut dyn FnMut(&mut Elab<'a>, Tm, Tm) -> R<Tm>) -> R<Tm> {
        self.expr(call, &mut |s, v| {
            let d = s.depth();
            let t = v.at(d);
            let (h, args) = super::items::spine(&t);
            let Term::Global(g) = &*h else { return unsupported(sp, "`f::step(args)`: the call does not elaborate to an application of `f`") };
            let g = *g;
            let (Some(n), Some(mut ty), Some(mut body)) = (s.env.global_arity(g), s.env.global_type(g), s.env.global_body(g)) else {
                return unsupported(sp, "`f::step(args)`: `f` has no body to unfold");
            };
            if args.len() != n as usize {
                return unsupported(sp, "`f::step(args)`: `f` is not applied to all of its arguments");
            }
            for _ in 0..n {
                let (Term::Pi { cod, .. }, Term::Lam { body: b, .. }) = (&*ty.clone(), &*body.clone()) else {
                    return unsupported(sp, "`f::step(args)`: unexpected shape of `f`'s definition");
                };
                ty = cod.clone();
                body = b.clone();
            }
            if matches!(&*ty, Term::Sort(_)) {
                return unsupported(sp, "`f::step(args)` needs a function with a value; a predicate unfolds with `unfold(f)`");
            }
            let stmt = mk::eq(super::tm::subst_closed(&ty, &args), t.clone(), super::tm::subst_closed(&body, &args));
            let pf: Tm = Rc::new(Term::Delta { def: g, args });
            k(s, pf, stmt)
        })
    }

    /// A lemma/law application: its proof term and its instantiated
    /// conclusion. Hypotheses are proven by the prover; a call of the
    /// enclosing lemma is `rec` (induction).
    pub fn lemma_app(&mut self, app: &'a Expr, relevant: bool) -> R<(Tm, Tm)> {
        // the arguments may bind (an exec call's `ensures`/`refines` facts
        // are `let`s around the rest): the application and its conclusion
        // come back at the outer depth, which is only possible when they do
        // not mention those binders ([`Elab::lemma_app_k`] keeps them in
        // scope instead)
        let d0 = self.depth();
        let span = app.span;
        let mut out: Option<(Tm, Tm)> = None;
        let _ = self.lemma_app_k(app, relevant, &mut |s, pf, ty| {
            let k = s.depth() - d0;
            if k > 0 {
                if (0..k).any(|i| sandblaster_kernel::util::occurs(&pf, i) || sandblaster_kernel::util::occurs(&ty, i)) {
                    return unsupported(span, "this lemma application uses the facts of a call in its arguments here: apply it as a statement (`lemma(..);`), or pass the call's value as a variable");
                }
                out = Some((shift(&pf, -(k as i64)), shift(&ty, -(k as i64))));
            } else {
                out = Some((pf, ty));
            }
            Ok(s.unit_val())
        })?;
        out.ok_or_else(|| ElabError { span, msg: "lemma application did not elaborate".into(), kind: ErrKind::Internal })
    }

    /// A lemma/law application in continuation-passing style: `k` gets its
    /// proof term and instantiated conclusion at the depth after its
    /// arguments, so the facts that elaborating an argument binds (the
    /// `ensures` and `refines` facts of an exec call such as `pos(0, i)`)
    /// stay in scope for the rest. Hypotheses are proven by the prover; a
    /// call of the enclosing lemma is `rec` (induction).
    pub fn lemma_app_k(&mut self, app: &'a Expr, relevant: bool, k: &mut dyn FnMut(&mut Elab<'a>, Tm, Tm) -> R<Tm>) -> R<Tm> {
        let ExprKind::Call { callee: Callee::Item(id, targs), args } = &app.kind else { return internal(app.span, "lemma application is not a call") };
        let span = app.span;
        let id = *id;
        if crate::resolve::prelude_lemma_kernel_name(&self.krate.item(id).path).is_some() {
            return self.prelude_lemma_app(id, targs, args, relevant, span, k);
        }
        self.exprs(args, &mut |s, vs| {
            let d = s.depth();
            let mut rel_args: Vec<Tm> = targs.iter().map(|t| s.ty(t, span)).collect::<R<Vec<_>>>()?;
            rel_args.extend(vs.iter().map(|v| v.at(d)));
            let is_rec = s.f.rec.as_ref().is_some_and(|r| r.item == Some(id));
            let (head, ty) = if is_rec {
                let r = s.f.rec.clone().unwrap();
                (None, r.ty.clone())
            } else {
                let g = s.item_global(id, span)?;
                (Some(mk::global(g)), s.env.global_type(g).ok_or_else(|| ElabError { span, msg: "lemma without type".into(), kind: ErrKind::Internal })?)
            };
            let gk = s.globals.get(&id).and_then(|x| match x {
                ItemGlobal::Def(g) => Some(*g),
                _ => None,
            });
            let kind = ObligationKind::CalleeRequires(gk.unwrap_or(sandblaster_kernel::term::GlobalId(u32::MAX)));
            // (the lemma's parameters and `requires` only: an implication
            // in its `ensures` stays in the conclusion)
            let arity = if is_rec { s.f.rec.as_ref().map(|r| r.arity as usize) } else { gk.and_then(|g| s.env.global_arity(g)).map(|a| a as usize) };
            let (app_t, all, concl_t) = s.apply_tele_upto(&ty, rel_args.into_iter().map(|a| (Rel::Rel, a)).collect(), None, head, Some(relevant), arity, &|_| kind.clone(), span)?;
            let pf = if is_rec {
                let r = s.f.rec.clone().unwrap();
                let proof = match &r.measure {
                    Some((m, w)) => Some(s.measure_proof(m, *w, r.arity, &all, span)?),
                    None => None,
                };
                Rc::new(Term::Rec { args: all, proof })
            } else {
                app_t
            };
            if s.depth() != d {
                return internal(span, "lemma arguments must not bind");
            }
            k(s, pf, concl_t)
        })
    }

    /// `using(f, ..)`: each lemma as a quantified fact (its statement, proven
    /// by the lemma itself), then the rest of the script.
    #[allow(clippy::too_many_arguments)]
    fn using_facts(&mut self, ids: &'a [ItemId], i: usize, rest: &'a [ScriptStmt], goal: Val, kind: ObligationKind, span: Span, sp: Span) -> R<Tm> {
        let Some(id) = ids.get(i) else { return self.script_rest(rest, goal, kind, span, sp) };
        if self.f.rec.as_ref().is_some_and(|r| r.item == Some(*id)) {
            return unsupported(sp, "`using` of the enclosing proof: apply the induction hypothesis with `ih(args);` or `by_induction(..)`");
        }
        let g = self.item_global(*id, sp)?;
        let ty = self.env.global_type(g).ok_or_else(|| ElabError { span: sp, msg: "lemma without type".into(), kind: ErrKind::Internal })?;
        self.fact_in("h_using", ty, mk::global(g), FactOrigin::Assert, sp, &mut |s| s.using_facts(ids, i + 1, rest, goal.clone(), kind.clone(), span, sp))
    }

    /// [`Elab::lemma_app_k`] attempted: the proof and conclusion when every
    /// hypothesis of the lemma is proven (their obligations are kept), else
    /// `None` with no trace (the obligations, diagnostics and failure flags
    /// of the attempt are dropped). The attempt's goals get a reduced step
    /// budget ([`TRY_BUDGET`]): an induction hypothesis whose hypotheses do
    /// not hold in a case must not cost a full search.
    pub fn try_lemma_app(&mut self, app: &'a Expr, relevant: bool) -> R<Option<(Tm, Tm)>> {
        let (no, nd, failed) = (self.obligations.len(), self.diags.list.len(), self.f.failed);
        let ns = self.f.slot_failures.as_ref().map(|v| v.len());
        let mut got: Option<(Tm, Tm)> = None;
        TRY_BUDGET.with(|c| c.set(c.get() + 1));
        let r = self.lemma_app_k(app, relevant, &mut |_, pf, ty| {
            got = Some((pf, ty));
            Ok(Rc::new(Term::Erased))
        });
        TRY_BUDGET.with(|c| c.set(c.get() - 1));
        let ok = r.is_ok() && got.is_some() && self.obligations[no..].iter().all(|o| o.proven());
        if std::env::var_os("SANDBLASTER_TRACE_TRY").is_some() {
            eprintln!("try in {}: {} ({:?}; {} obligation(s), {} unproven)", self.f.name, if ok { "kept" } else { "dropped" }, r.as_ref().err().map(|e| e.msg.clone()), self.obligations.len() - no, self.obligations[no..].iter().filter(|o| !o.proven()).count());
            if let Some((_, ty)) = &got {
                eprintln!("   concl: {}", self.show_tm(ty));
            }
        }
        if ok {
            return Ok(got);
        }
        self.obligations.truncate(no);
        self.diags.list.truncate(nd);
        self.f.failed = failed;
        if let (Some(v), Some(n)) = (self.f.slot_failures.as_mut(), ns) {
            v.truncate(n);
        }
        // its hypotheses do not all hold here: the implication instead
        self.implication_app(app)
    }

    /// The implication form of a lemma application: `Π(h : R[args]).. Q[args]`
    /// (the lemma's `requires` at the arguments as hypotheses), proven by
    /// `λh.. lemma(args, h..)` — the recursive application with its measure
    /// proof for the enclosing lemma (an induction hypothesis whose
    /// hypotheses hold only in some cases). A quantified fact: `follows()`
    /// chains it (∀-facts, DESIGN.md §8.1 step 7). `None` when the lemma has
    /// no hypotheses or the measure decrease is not proven.
    fn implication_app(&mut self, app: &'a Expr) -> R<Option<(Tm, Tm)>> {
        let ExprKind::Call { callee: Callee::Item(id, targs), args } = &app.kind else { return Ok(None) };
        let (id, span) = (*id, app.span);
        if !targs.is_empty() || crate::resolve::prelude_lemma_kernel_name(&self.krate.item(id).path).is_some() {
            return Ok(None);
        }
        let (no, nd, failed) = (self.obligations.len(), self.diags.list.len(), self.f.failed);
        let ns = self.f.slot_failures.as_ref().map(|v| v.len());
        let mut out: Option<(Tm, Tm)> = None;
        let r = self.exprs(args, &mut |s, vs| {
            let d = s.depth();
            let rel_args: Vec<Tm> = vs.iter().map(|v| v.at(d)).collect();
            let rec = s.f.rec.clone().filter(|r| r.item == Some(id));
            let ty = match &rec {
                Some(r) => r.ty.clone(),
                None => {
                    let g = s.item_global(id, span)?;
                    s.env.global_type(g).ok_or_else(|| ElabError { span, msg: "lemma without type".into(), kind: ErrKind::Internal })?
                }
            };
            let mut t = ty;
            for _ in 0..rel_args.len() {
                let Term::Pi { cod, .. } = &*t.clone() else { return Ok(Rc::new(Term::Erased)) };
                t = cod.clone();
            }
            let rest = super::tm::subst_closed(&t, &rel_args);
            let mut hyps: Vec<(sandblaster_kernel::term::Name, Rel, Tm)> = Vec::new();
            let mut cur = rest.clone();
            while let Term::Pi { name, rel, dom, cod } = &*cur.clone() {
                hyps.push((name.clone(), *rel, dom.clone()));
                cur = cod.clone();
            }
            if hyps.is_empty() {
                return Ok(Rc::new(Term::Erased));
            }
            let m = hyps.len() as i64;
            let mut all: Vec<Tm> = rel_args.iter().map(|a| shift(a, m)).collect();
            all.extend((0..m as u32).rev().map(mk::var));
            let body = match &rec {
                Some(r) => {
                    let proof = match &r.measure {
                        Some((mm, w)) => {
                            // the measure is over the parameters (the hypotheses'
                            // slots are never referenced by it)
                            let mut margs = rel_args.clone();
                            margs.extend((0..m).map(|_| Rc::new(Term::Erased)));
                            if (r.arity as usize) > margs.len() {
                                return Ok(Rc::new(Term::Erased));
                            }
                            let mp = s.measure_proof(mm, *w, r.arity, &margs, span)?;
                            if super::tm::has_erased(&mp) {
                                return Ok(Rc::new(Term::Erased));
                            }
                            Some(shift(&mp, m))
                        }
                        None => None,
                    };
                    Rc::new(Term::Rec { args: all, proof })
                }
                None => {
                    let g = s.item_global(id, span)?;
                    let n = rel_args.len();
                    all.into_iter().enumerate().fold(mk::global(g), |f, (i, a)| {
                        let rel = if i < n { Rel::Rel } else { hyps[i - n].1 };
                        Rc::new(Term::App { rel, fun: f, arg: a })
                    })
                }
            };
            let mut pf = body;
            for (name, rel, dom) in hyps.iter().rev() {
                pf = Rc::new(Term::Lam { name: name.clone(), rel: *rel, dom: dom.clone(), body: pf });
            }
            out = Some((pf, rest));
            Ok(Rc::new(Term::Erased))
        });
        let ok = r.is_ok() && out.is_some() && self.obligations[no..].iter().all(|o| o.proven());
        if std::env::var_os("SANDBLASTER_TRACE_TRY").is_some() {
            eprintln!("implication in {}: {}", self.f.name, if ok { "kept" } else { "dropped" });
            if let Some((pf, ty)) = &out {
                eprintln!("   type: {}\n   proof: {}\n   depth {}", self.show_tm(ty), self.show_tm(pf), self.depth());
            }
        }
        if ok {
            return Ok(out);
        }
        self.obligations.truncate(no);
        self.diags.list.truncate(nd);
        self.f.failed = failed;
        if let (Some(v), Some(n)) = (self.f.slot_failures.as_mut(), ns) {
            v.truncate(n);
        }
        Ok(None)
    }

    /// An application of a prelude lemma through its surface signature
    /// ([`crate::auto::surface`]): type arguments and surface arguments fill
    /// the kernel telescope by role; hypotheses are proven by the prover.
    #[allow(clippy::too_many_arguments)]
    fn prelude_lemma_app(&mut self, id: ItemId, targs: &'a [Ty], args: &'a [Expr], relevant: bool, span: Span, k: &mut dyn FnMut(&mut Elab<'a>, Tm, Tm) -> R<Tm>) -> R<Tm> {
        let g = self.item_global(id, span)?;
        let sig = crate::auto::surface::sig(&self.env, g).ok_or_else(|| ElabError { span, msg: "prelude lemma without a surface signature".into(), kind: ErrKind::Internal })?;
        let ty = self.env.global_type(g).ok_or_else(|| ElabError { span, msg: "lemma without type".into(), kind: ErrKind::Internal })?;
        self.exprs(args, &mut |s, vs| {
            let d = s.depth();
            let tys: Vec<Tm> = targs.iter().map(|t| s.ty(t, span)).collect::<R<Vec<_>>>()?;
            let mut app = mk::global(g);
            let mut all: Vec<Tm> = Vec::new();
            let mut t = ty.clone();
            for role in &sig.roles {
                let Term::Pi { rel, dom, cod, .. } = &*t.clone() else { return internal(span, "prelude lemma telescope") };
                let arg = match role {
                    crate::auto::surface::Role::Type(i) => tys.get(*i).cloned().ok_or_else(|| ElabError { span, msg: "missing type argument".into(), kind: ErrKind::Internal })?,
                    crate::auto::surface::Role::Value { index, list } => {
                        let v = vs.get(*index).map(|v| v.at(d)).ok_or_else(|| ElabError { span, msg: "missing lemma argument".into(), kind: ErrKind::Internal })?;
                        let v = if *list { mk::fst(mk::snd(v)) } else { v };
                        // the argument must have the binder's type at the
                        // arguments given so far: a value that also occurs
                        // in a type (an array length) must agree with the
                        // type argument (`::<u8, [u8; 32]>(16, ..)` is
                        // wrong); an ill-typed application would only be
                        // dropped later, silently
                        // (an argument with erased proofs, in exec mode,
                        // cannot be checked here; a budget exhausted is no
                        // verdict)
                        let want = super::tm::subst_closed(dom, &all);
                        let ok = super::tm::any_node(&v, &mut |n| matches!(n, Term::Erased))
                            || match s.eval(&want) {
                                Ok(wv) => match s.env.check(&s.f.scope.ctx, &v, &wv, &mut s.budget()) {
                                    Ok(()) => true,
                                    Err(e) => matches!(e.kind, sandblaster_kernel::api::KernelErrorKind::Eval(_)),
                                },
                                Err(_) => true,
                            };
                        if !ok {
                            let name = sig.params.get(*index).map(|p| p.0.clone()).unwrap_or_else(|| format!("#{index}"));
                            let lemma = crate::resolve::prelude_lemma_kernel_name(&s.krate.item(id).path).map(|k| format!("sandblaster::lemmas::{k}")).unwrap_or_else(|| s.krate.item(id).path.to_string());
                            s.diags.push(
                                Diagnostic::error(DiagKind::Script, span, format!("argument `{name}` of `{lemma}` does not have the type that the type arguments and the arguments before it give it: expected `{}`", s.show_tm(&want)))
                                    .note("a value that also occurs in a type (an array length) must agree with the type arguments: `chunks_arrays_flatten::<u8, [u8; 32]>(32, ds)`"),
                            );
                            return unsupported(span, format!("ill-typed argument `{name}` of a lemma application"));
                        }
                        v
                    }
                    crate::auto::surface::Role::Hyp => {
                        let target = super::tm::subst_closed(dom, &all);
                        let target = super::recert::recertify(&s.env, &s.f.scope.ctx, &target);
                        s.prove(ObligationKind::CalleeRequires(g), span, &target, relevant && *rel == Rel::Rel)?
                    }
                };
                app = Rc::new(Term::App { rel: *rel, fun: app, arg: arg.clone() });
                all.push(arg);
                t = cod.clone();
            }
            if s.depth() != d {
                return internal(span, "lemma arguments must not bind");
            }
            let concl = super::tm::subst_closed(&t, &all);
            let concl = super::recert::recertify(&s.env, &s.f.scope.ctx, &concl);
            k(s, app, concl)
        })
    }

    /// A proof term: a lemma application, or a ghost expression (a proof
    /// binder); with its type.
    fn proof_term(&mut self, e: &'a Expr, relevant: bool) -> R<(Tm, Tm)> {
        if e.ty == Ty::Proof
            && let ExprKind::Call { .. } = &e.kind
        {
            return self.lemma_app(e, relevant);
        }
        if let ExprKind::Local(l) = &e.kind {
            let t = self.local_tm(*l, e.span)?;
            let lvl = self.f.scope.local(*l).unwrap();
            let ty = self.f.scope.ctx.entries[lvl as usize].ty.clone();
            let tyt = self.quote(&ty, None);
            return Ok((t, tyt));
        }
        let t = self.pure_expr(e)?;
        let mut b = self.budget();
        let ty = self.env.infer(&self.f.scope.ctx, &t, &mut b).map_err(|x| ElabError { span: e.span, msg: format!("ill-typed proof term: {x}"), kind: ErrKind::Unsupported })?;
        let tyt = self.quote(&ty, None);
        Ok((t, tyt))
    }

    /// `use_hyp(i, args..)` ([`ScriptKind::UseHyp`]): `t : ty` (terms at
    /// the current depth) applied binder by binder — a relevant binder to
    /// the next argument, an irrelevant one (a `requires`, a `Nat` range)
    /// to its proof by the prover — until the arguments are used up and the
    /// next binder is relevant, or no binder is left; the result is an
    /// irrelevant fact (the hypothesis is one), then the rest of the block.
    #[allow(clippy::too_many_arguments)]
    fn use_hyp_args(&mut self, t: Tm, ty: Tm, args: &'a [Expr], i: usize, rest: &'a [ScriptStmt], goal: Val, kind: ObligationKind, span: Span, sp: Span) -> R<Tm> {
        let d0 = self.depth();
        let pi = super::tm::head_unfold(&self.env, &ty, &|x| matches!(x, Term::Pi { .. }));
        match pi.as_deref() {
            // a proof binder: a `requires` (irrelevant) or a `Nat` range or
            // `requires` of a law's statement (named `h_..`; the elaborator
            // never names a data binder so)
            Some(Term::Pi { rel, dom, cod, name }) if *rel == Rel::Irr || name.starts_with("h_") => {
                let (dom, cod, rel) = (dom.clone(), cod.clone(), *rel);
                let p = self.prove(ObligationKind::Assert, sp, &dom, rel == Rel::Rel)?;
                let t2 = Rc::new(Term::App { rel, fun: t, arg: p.clone() });
                let ty2 = super::tm::simp_redexes(&super::tm::subst0(&cod, &p));
                self.use_hyp_args(t2, ty2, args, i, rest, goal, kind, span, sp)
            }
            Some(Term::Pi { rel: Rel::Rel, cod, .. }) if i < args.len() => {
                let cod = cod.clone();
                self.expr(&args[i], &mut |s, v| {
                    let d = s.depth();
                    let k = (d - d0) as i64;
                    let w = v.at(d);
                    let t2 = Rc::new(Term::App { rel: Rel::Rel, fun: shift(&t, k), arg: w.clone() });
                    let ty2 = super::tm::simp_redexes(&super::tm::subst0(&sandblaster_kernel::util::shift_from(&cod, k, 1), &w));
                    s.use_hyp_args(t2, ty2, args, i + 1, rest, goal.clone(), kind.clone(), span, sp)
                })
            }
            _ if i < args.len() => unsupported(args[i].span, format!("`use_hyp`: {} argument(s) too many for the hypothesis", args.len() - i)),
            _ => {
                // the kernel checks the application against the fact's type;
                // the fact is relevant when the application is (the
                // hypothesis and every data argument usable as data), so an
                // `exists` it concludes gives witnesses to relevant goals
                let unit_ty = { let u = mk::ind(self.p.unit, vec![]); self.eval(&u)? };
                let check = |s: &mut Self, rel: Rel| {
                    let mut b = s.budget();
                    s.env.check(&s.f.scope.ctx, &Rc::new(Term::Let { name: Rc::from("h"), rel, ty: ty.clone(), val: t.clone(), body: s.unit_val() }), &unit_ty, &mut b)
                };
                let rel = if check(self, Rel::Rel).is_ok() {
                    Rel::Rel
                } else if let Err(e) = check(self, Rel::Irr) {
                    return unsupported(sp, format!("`use_hyp`: the instance is ill-typed: {e}"));
                } else {
                    Rel::Irr
                };
                let saved = self.f.scope.clone();
                self.push_fact_rel("h_hyp", rel, &ty, Some(&t), FactOrigin::LemmaHyp, sp)?;
                let body = self.script_rest(rest, goal, kind, span, sp);
                self.f.scope = saved;
                Ok(mk::let_("h_hyp", rel, ty, t, body?))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn witness(&mut self, es: &'a [Expr], i: usize, rest: &'a [ScriptStmt], goal: Val, kind: ObligationKind, span: Span, sp: Span) -> R<Tm> {
        let Some(e) = es.get(i) else { return self.script_rest(rest, goal, kind, span, sp) };
        let d0 = self.depth();
        let g = goal.at(d0);
        // the range `0 <= x` of a `Nat` binder just instantiated (`exists(|x:
        // Nat, y: T| ..)` is `Σ x. Σ (h_nat : 0 <= x). Σ y. ..`): proven, not
        // given a witness, so the next witness goes to the next binder
        if i > 0
            && let Some(sigma_t) = super::tm::head_unfold(&self.env, &g, &|t| matches!(t, Term::Sigma { .. }))
            && let Term::Sigma { name, fst, snd, .. } = &*sigma_t
            && &**name == "h_nat"
        {
            let (fst, snd) = (fst.clone(), snd.clone());
            let relevant = self.f.mode == Mode::Proof;
            let p0 = self.prove(ObligationKind::Assert, sp, &fst, relevant)?;
            let next_t = super::tm::simp_redexes(&super::tm::subst0(&snd, &p0));
            let p = self.witness(es, i, rest, Val::new(next_t, d0), kind, span, sp)?;
            return Ok(mk::pair(sigma_t.clone(), p0, p));
        }
        // on the goal *term* (an `exists` behind spec functions): the next
        // goal is the body instantiated with the witness, by substitution
        if let Some(sigma_t) = super::tm::head_unfold(&self.env, &g, &|t| matches!(t, Term::Sigma { .. })) {
            let Term::Sigma { snd: snd_t, .. } = &*sigma_t else { return internal(sp, "witness: Σ") };
            let snd_t = snd_t.clone();
            return self.expr(e, &mut |s, v| {
                let d = s.depth();
                let w = v.at(d);
                let k = (d - d0) as i64;
                let next_t = super::tm::simp_redexes(&super::tm::subst0(&sandblaster_kernel::util::shift_from(&snd_t, k, 1), &w));
                let p = s.witness(es, i + 1, rest, Val::new(next_t, d), kind.clone(), span, sp)?;
                Ok(mk::pair(shift(&sigma_t, k), w, p))
            });
        }
        let gv = self.eval(&g)?;
        let Value::Sigma { snd, .. } = &*gv else { return unsupported(sp, "`witness` needs an `exists` goal") };
        let snd = snd.clone();
        let sigma_t = self.quote(&gv, None);
        self.expr(e, &mut |s, v| {
            let d = s.depth();
            let w = v.at(d);
            let wv = s.eval(&w)?;
            let mut env = (*snd.env.0).clone();
            env.push(EnvEntry::Rel(wv));
            let next = s.eval_in(&VEnv(Rc::new(env)), &snd.body)?;
            let next_t = s.quote(&next, None);
            let p = s.witness(es, i + 1, rest, Val::new(next_t, d), kind.clone(), span, sp)?;
            Ok(mk::pair(shift(&sigma_t, (d - d0) as i64), w, p))
        })
    }

    /// Unfolds applications of `g` in the goal (`delta`, §5.6), on the goal
    /// *term*: the other calls stay folded (a closing statement after
    /// `unfold` sees only what was unfolded).
    #[allow(clippy::too_many_arguments)]
    fn unfold_goal(&mut self, g: sandblaster_kernel::term::GlobalId, goal: Val, rest: &'a [ScriptStmt], kind: ObligationKind, span: Span, sp: Span, n: u32, budget: u32) -> R<Tm> {
        let d = self.depth();
        let gt = goal.at(d);
        // a transparent non-recursive definition: replace its applications
        // in the goal *term* by the instantiated body (convertible, no proof
        // needed); the rest of the goal stays folded
        if n == 0
            && let Some(ng) = super::tm::unfold_syntactic(&self.env, &gt, g)
        {
            return self.hoist_facts(Val::new(super::tm::simp_redexes(&ng), d), rest, kind, span, sp, 0);
        }
        // otherwise (recursive or opaque): `transport` along `delta(g;
        // args)` for an application in the goal term
        let arity = self.env.global_arity(g).unwrap_or(0) as usize;
        // (an application only under binders — in an arm of the unfolded
        // body of an exec function — when `unfold(f)` finds none outside)
        // (every application written in the goal's logical structure is
        // unfolded, up to 8 — each conjunct of a `&&` goal, the second under
        // the first's proof, and both sides of `||`, `prop_apps` — but the
        // later rounds take no more of those steps than the goal had such
        // applications, so the calls a recursive body brings in stay folded;
        // calls in the arms of a boolean `&&` or `if` stay folded as before)
        let budget = if n == 0 { prop_apps(&gt, g, arity).len().min(8) as u32 } else { budget };
        let found = if n == 0 {
            find_app_prop(&gt, g, arity).or_else(|| find_app_under(&gt, g, arity))
        } else {
            find_app(&gt, g, arity).or_else(|| if n < budget { find_app_prop(&gt, g, arity) } else { None })
        };
        let step = match found {
            Some(occ) => self.delta_motive(g, &gt, &occ, sp)?,
            None => None,
        };
        let Some((occ, m, rhs_t, r_t, delta)) = step else {
            if n == 0 {
                self.diags.push(Diagnostic::warning(DiagKind::Script, sp, "`unfold`: no application of this function in the goal").note("the goal is unchanged; `unfold(f)` rewrites the calls of `f` written in the goal (after the earlier steps)"));
                return self.script_rest(rest, goal, kind, span, sp);
            }
            return self.hoist_facts(goal, rest, kind, span, sp, 0);
        };
        let ngt = super::tm::simp_redexes(&super::tm::subst0(&m, &rhs_t));
        let p = if n < 8 { self.unfold_goal(g, Val::new(ngt, d), rest, kind, span, sp, n + 1, budget)? } else { self.hoist_facts(Val::new(ngt, d), rest, kind, span, sp, 0)? };
        let eq = mk::apps(mk::global(self.p.g("eq::sym")), [(Rel::Rel, r_t.clone()), (Rel::Rel, occ.clone()), (Rel::Rel, rhs_t.clone()), (Rel::Rel, delta)]);
        Ok(Rc::new(Term::Transport { ty: r_t, lhs: rhs_t, rhs: occ, eq, motive: m, val: p }))
    }

    /// For a `bv()` goal `Eq(A, l, r)` whose sides evaluate to arrays or
    /// lists of words of the same length: the first index whose elements
    /// the word normalizer does not identify, with their normal forms.
    fn bv_first_difference(&mut self, g: &Tm) -> Option<String> {
        // only an array or list result (`Array T N`, evaluated to
        // `Σ(l : List T). ..`, or `List(T)`)
        let Term::Eq { ty, lhs: l_t, rhs: r_t } = &**g else { return None };
        let tv = self.eval(ty).ok()?;
        let ty_t = self.quote(&tv, None);
        let is_list = |t: &Tm| matches!(&**t, Term::Ind { ind, params } if *ind == self.p.list && params.len() == 1);
        let (h, args) = super::items::spine(&ty_t);
        let shaped = match (&*h, &*ty_t) {
            (Term::Global(x), _) if *x == self.p.g("Array") && args.len() == 2 => true,
            (_, Term::Sigma { fst, .. }) => is_list(fst),
            _ => is_list(&ty_t),
        };
        if !shaped {
            return None;
        }
        // the word normalizer's view: opaque definitions (loops) unfold; the
        // elements are read off the values and quoted one by one, with
        // sharing (the rounds of a hash are a DAG)
        let elems = |me: &Self, t: &Tm| -> Option<Vec<Tm>> {
            use sandblaster_kernel::value::{Arg, Value as W};
            let mut b = sandblaster_kernel::value::Budget { steps: me.opts.goal_budget };
            let venv = me.f.scope.venv.clone();
            let tv = me.env.eval_transparent(&venv, sandblaster_kernel::term::Lvl(me.depth()), t, &mut b).ok()?;
            let mut cur = match &*tv {
                W::Pair { fst, .. } => fst.clone(),
                _ => tv.clone(),
            };
            let mut out = Vec::new();
            loop {
                match &*cur.clone() {
                    W::Ctor { ind, ctor: 0, .. } if *ind == me.p.list => return Some(out),
                    W::Ctor { ind, ctor: 1, args, .. } if *ind == me.p.list && args.len() == 2 => {
                        let (Arg::Rel(h), Arg::Rel(tl)) = (&args[0], &args[1]) else { return None };
                        out.push(me.env.quote_typed(&me.f.scope.ctx, h, None, true));
                        cur = tl.clone();
                    }
                    _ => return None,
                }
            }
        };
        let (ls, rs) = (elems(self, l_t)?, elems(self, r_t)?);
        if ls.len() != rs.len() {
            return Some(format!("the sides have {} and {} elements", ls.len(), rs.len()));
        }
        for (i, (a, b)) in ls.iter().zip(&rs).enumerate() {
            // the kernel's word normalizer, as a diagnostic (the verdict on
            // the whole goal was already the kernel's)
            let mut bud = sandblaster_kernel::value::Budget { steps: self.opts.goal_budget.saturating_mul(4) };
            match sandblaster_kernel::bvnorm::decide(&self.env, &self.f.scope.ctx, a, b, sandblaster_kernel::bvnorm::BvOptions { tripwire: false }, &mut bud) {
                Ok(sandblaster_kernel::bvnorm::BvVerdict::Equal) => {}
                Ok(sandblaster_kernel::bvnorm::BvVerdict::Different(m) | sandblaster_kernel::bvnorm::BvVerdict::TripwireMismatch(m)) => {
                    let detail: String = m.chars().take(1200).collect();
                    return Some(format!("result element {i} (of {}) differs: {detail}", ls.len()));
                }
                Err(_) => return None,
            }
        }
        None
    }

    /// After `unfold(f)` of an exec function: the facts of its body — the
    /// irrelevant `let`s its elaboration binds (a callee's `ensures` and
    /// refinement `h_ens`/`h_ref`, slice bounds), wherever in the unfolded
    /// goal they depend only on the script's context — become facts of the
    /// script, so the prover (and a later `unfold` of the callee, whose
    /// motive would otherwise have to abstract the callee inside those
    /// facts' types) sees them. Each is removed from the goal by ζ with its
    /// variable replaced by the hoisted fact (convertible: an irrelevant
    /// proof is any proof).
    #[allow(clippy::too_many_arguments)]
    fn hoist_facts(&mut self, goal: Val, rest: &'a [ScriptStmt], kind: ObligationKind, span: Span, sp: Span, n: u32) -> R<Tm> {
        self.hoist_facts_then(goal, rest, false, kind, span, sp, n)
    }

    /// The steps of a branch of a script `match`/`if`: the facts of the
    /// unfolded body that the branch exposes (a callee's `ensures` or
    /// refinement on the branch's pattern variables, which could not be
    /// hoisted before the branch was taken) become facts first, as after
    /// `unfold` ([`Elab::hoist_facts`]).
    pub(super) fn branch_script(&mut self, steps: &'a [ScriptStmt], goal: Val, kind: ObligationKind, span: Span) -> R<Tm> {
        // the branch's goal is the goal at the pattern: its match on the
        // constructor reduces (convertible), exposing the branch's facts
        let d = self.depth();
        let gt = goal.at(d);
        let env = &self.env;
        let callee = |v: &Tm| {
            let (h, _) = super::items::spine(v);
            matches!(&*h, Term::Global(g) if env.global_kind(*g) == Some(DefKind::Ensures))
        };
        if find_hoistable_by(&gt, &callee).is_none() {
            let reduced = super::tm::simp_redexes(&gt);
            // (a redex of a path-equation idiom whose `refl` argument was
            // not generalized would be ill-typed once reduced: checked)
            let mut b = self.budget();
            if find_hoistable_by(&reduced, &callee).is_some() && matches!(self.env.infer(&self.f.scope.ctx, &reduced, &mut b), Ok(t) if matches!(&*t, Value::Sort(_))) {
                return self.hoist_facts_then(Val::new(reduced, d), steps, true, kind, span, span, 0);
            }
        }
        self.hoist_facts_then(goal, steps, true, kind, span, span, 0)
    }

    /// [`Elab::hoist_facts`]; then the statements `rest` (`branch`: the
    /// whole block of a branch, [`Elab::script`]; else the rest of a block,
    /// [`Elab::script_rest`]).
    #[allow(clippy::too_many_arguments)]
    fn hoist_facts_then(&mut self, goal: Val, rest: &'a [ScriptStmt], branch: bool, kind: ObligationKind, span: Span, sp: Span, n: u32) -> R<Tm> {
        let d = self.depth();
        let gt = goal.at(d);
        // in a branch, the callee facts only (a callee's `ensures` or
        // refinement, `f::ensures`/`f::refines`), not the proofs of the
        // goal's own obligations
        let env = &self.env;
        let callee = |v: &Tm| {
            let (h, _) = super::items::spine(v);
            matches!(&*h, Term::Global(g) if env.global_kind(*g) == Some(DefKind::Ensures))
        };
        let pick: &dyn Fn(&Tm) -> bool = if branch { &callee } else { &|_| true };
        let found = if n < 32 { find_hoistable_by(&gt, pick) } else { None };
        let Some((name, p_ty, pf)) = found else {
            return if branch { self.script(rest, goal, kind, span) } else { self.script_rest(rest, goal, kind, span, sp) };
        };
        let g2 = hoist_one_by(&gt, pick);
        let saved = self.f.scope.clone();
        let r = (|| -> R<Tm> {
            self.push_fact_rel(&name, Rel::Irr, &p_ty, Some(&pf), FactOrigin::CalleeEnsures(self.p.g("eq::sym")), sp)?;
            self.hoist_facts_then(Val::new(g2, d + 1), rest, branch, kind, span, sp, n + 1)
        })();
        self.f.scope = saved;
        Ok(mk::let_(&name, Rel::Irr, p_ty, pf, r?))
    }

    /// For an application `occ = g a..` in the goal term `gt`: the motive
    /// generalizing its syntactic occurrences, the instantiated body of `g`
    /// (a term), the result type and `delta(g; a..)`. `None` if the motive is
    /// ill-typed or `g` has no defining equation (a proposition).
    fn delta_motive(&mut self, g: sandblaster_kernel::term::GlobalId, gt: &Tm, occ: &Tm, sp: Span) -> R<Option<(Tm, Tm, Tm, Tm, Tm)>> {
        let (_, args) = super::items::spine(occ);
        let delta = Rc::new(Term::Delta { def: g, args: args.clone() });
        let mut b = self.budget();
        let dty = match self.env.infer(&self.f.scope.ctx, &delta, &mut b) {
            Ok(t) => t,
            Err(e) => {
                if self.env.global_type_value(g).is_some() {
                    return unsupported(sp, format!("`unfold`: {e}"));
                }
                return Ok(None);
            }
        };
        let Value::Eq { ty: r, .. } = &*dty else { return internal(sp, "delta type") };
        let r_t = self.quote(r, None);
        let Some(m) = super::tm::abstract_syntactic(&self.env, gt, occ) else { return Ok(None) };
        // the motive must be a proposition over the generalized application
        let rv = r.clone();
        let saved = self.f.scope.clone();
        self.push_v("y", Rel::Rel, rv);
        let mut b = self.budget();
        let ok = matches!(self.env.infer(&self.f.scope.ctx, &m, &mut b), Ok(t) if matches!(&*t, Value::Sort(_)));
        self.f.scope = saved;
        if !ok {
            return Ok(None);
        }
        // the body instantiated with the arguments, as a term (calls in it
        // stay folded)
        let Some(body) = self.env.global_body(g) else { return Ok(None) };
        let mut inner = body;
        for _ in 0..args.len() {
            let Term::Lam { body, .. } = &*inner.clone() else { return Ok(None) };
            inner = body.clone();
        }
        let rhs_t = super::tm::simp_redexes(&super::tm::subst_closed(&inner, &args));
        Ok(Some((occ.clone(), m, rhs_t, r_t, delta)))
    }

    #[allow(clippy::too_many_arguments)]
    fn rewrite_step(&mut self, eq: &'a Expr, rev: bool, motive: Option<&'a (LocalId, Expr)>, rest: &'a [ScriptStmt], goal: Val, kind: ObligationKind, span: Span, sp: Span) -> R<Tm> {
        let relevant = self.f.mode == Mode::Proof;
        // `rewrite(a == b)`: the equation is proven first (like `assert`),
        // typically from a hypothesis
        let (pf, ty) = if matches!(eq.ty, Ty::Bool | Ty::Prop) {
            let p = self.prop(eq)?;
            let pf = self.prove(ObligationKind::Assert, sp, &p, relevant)?;
            (pf, p)
        } else {
            self.proof_term(eq, relevant)?
        };
        let d = self.depth();
        // on the goal *term*: generalize the syntactic occurrences of the
        // equation's side (the goal's value may be huge, see
        // `tm::abstract_syntactic`)
        if motive.is_none()
            && let Term::Eq { ty: a_t, lhs: l_t, rhs: r_t } = &*ty
        {
            let (from_t, to_t) = if rev { (r_t.clone(), l_t.clone()) } else { (l_t.clone(), r_t.clone()) };
            let gt = goal.at(d);
            // a variable side (an array variable, whose value is
            // eta-expanded and would be quoted with `Erased` proofs): its
            // occurrences, by level
            let m = match &*from_t {
                Term::Var(sandblaster_kernel::term::Idx(i)) if *i < d => Some(abstract_level(&gt, d, d - 1 - *i)),
                _ => super::tm::abstract_syntactic(&self.env, &gt, &from_t),
            };
            if let Some(m) = m {
                let av = self.eval(a_t)?;
                let saved = self.f.scope.clone();
                self.push_v("y", Rel::Rel, av);
                let mut b = self.budget();
                let ok = matches!(self.env.infer(&self.f.scope.ctx, &m, &mut b), Ok(t) if matches!(&*t, Value::Sort(_)));
                self.f.scope = saved;
                if ok {
                    let ng = super::tm::simp_redexes(&super::tm::subst0(&m, &to_t));
                    let p = self.script_rest(rest, Val::new(ng, d), kind, span, sp)?;
                    let e = if rev { pf } else { mk::apps(mk::global(self.p.g("eq::sym")), [(Rel::Rel, a_t.clone()), (Rel::Rel, from_t.clone()), (Rel::Rel, to_t.clone()), (Rel::Rel, pf)]) };
                    return Ok(Rc::new(Term::Transport { ty: a_t.clone(), lhs: to_t, rhs: from_t, eq: e, motive: m, val: p }));
                }
            }
        }
        let tv = self.eval(&ty)?;
        let Value::Eq { ty: a, lhs, rhs } = &*tv else { return unsupported(sp, "`rewrite` needs an equation") };
        let (from, to) = if rev { (rhs.clone(), lhs.clone()) } else { (lhs.clone(), rhs.clone()) };
        let gt = goal.at(d);
        let gv = self.eval(&gt)?;
        let m = match motive {
            Some((x, body)) => {
                let at = self.quote(a, None);
                let saved = self.f.scope.clone();
                let lvl = self.push(&self.local_decl(*x).name.clone(), Rel::Rel, &at, None)?;
                self.f.scope.locals.insert(*x, lvl);
                let r = self.prop(body);
                self.f.scope = saved;
                r?
            }
            None => {
                let mut b = self.budget();
                super::basic::abstract_all(&self.env, &self.f.scope.ctx, &gv, &from, &mut b).map_err(|e| ElabError { span: sp, msg: format!("`rewrite`: {e}"), kind: ErrKind::Unsupported })?
            }
        };
        let mut env = (*self.f.scope.venv.0).clone();
        env.push(EnvEntry::Rel(to.clone()));
        let ng = self.eval_in(&VEnv(Rc::new(env)), &m)?;
        let ngt = self.quote(&ng, None);
        let (at, ft, tt) = (self.quote(a, None), self.quote(&from, None), self.quote(&to, None));
        // quoted values may carry `Erased` in irrelevant positions: such a
        // step would only be rejected by the kernel later
        if [&m, &ngt, &ft, &tt].iter().any(|t| super::tm::has_erased(t)) {
            return unsupported(sp, "`rewrite`: the rewritten goal cannot be stated (a side of the equation does not occur in the goal as written, and its evaluated form hides proofs); rewrite with an equation whose side is written in the goal, or give the motive: `rewrite(h, |x| p)`");
        }
        let p = self.script_rest(rest, Val::new(ngt, d), kind, span, sp)?;
        // transport(A, to, from, e : Eq(A, to, from), m, p) : m[from] = goal
        let e = if rev { pf } else { mk::apps(mk::global(self.p.g("eq::sym")), [(Rel::Rel, at.clone()), (Rel::Rel, ft.clone()), (Rel::Rel, tt.clone()), (Rel::Rel, pf)]) };
        Ok(Rc::new(Term::Transport { ty: at, lhs: tt, rhs: ft, eq: e, motive: m, val: p }))
    }

    /// A script `match`: refinement for a variable scrutinee of an
    /// inductive type with single-level constructor patterns; otherwise the
    /// pattern compiler with the goal unchanged.
    #[allow(clippy::too_many_arguments)]
    fn script_match(&mut self, scrut: &'a Expr, arms: &'a [ScriptArm], goal: Val, kind: ObligationKind, span: Span, sp: Span) -> R<Tm> {
        // arms as HIR match arms (bodies are indices into `arms`)
        let harms: Vec<Arm> = arms.iter().enumerate().map(|(i, a)| Arm { pat: a.pat.clone(), guard: None, body: Expr::new(ExprKind::Lit(Lit::Int(i as u128)), Ty::usize(), a.span), span: a.span }).collect();
        let harms: &'a [Arm] = self.arena_arms(harms);
        let expanded: &'a [Arm] = self.expanded_arms(harms);
        // a variable scrutinee: refine the goal and the dependent facts
        let pats: Vec<&'a Pat> = expanded.iter().map(|a| &a.pat).collect();
        let arm_steps: Vec<&'a [ScriptStmt]> = expanded
            .iter()
            .map(|a| match &a.body.kind {
                ExprKind::Lit(Lit::Int(n)) => &arms[*n as usize].steps[..],
                _ => &[][..],
            })
            .collect();
        if let Some(r) = self.refine_match(scrut, &pats, &arm_steps, &goal, &kind, span) {
            return r;
        }
        let refine = self.refinable(scrut);
        // a slice or an array is not an inductive value: its patterns are
        // compiled to length tests on `bool`, which a motive over the slice
        // would be instantiated with (the goal of an arm then mentions
        // `false` for the slice). Its arms keep the goal; the pattern's
        // bindings (`init`, `last`, `tail`: sub-slices and elements of the
        // scrutinee) and the length tests are their facts.
        let slice_scrut = matches!(scrut.ty.peel_refs(), Ty::Slice(_) | Ty::Array(..));
        self.expr(scrut, &mut |s, v| {
            let d = s.depth();
            let answer = match refine {
                _ if slice_scrut => Answer::Tm(goal.clone()),
                _ if let Some(m) = s.syntactic_motive(&goal, &v.at(d), &scrut.ty, sp) => Answer::Motive(m),
                Some(_) => {
                    let gv = s.eval(&goal.at(d))?;
                    let sv = s.eval(&v.at(d))?;
                    let mut b = s.budget();
                    match super::basic::abstract_all(&s.env, &s.f.scope.ctx, &gv, &sv, &mut b) {
                        Ok(m) => Answer::Motive(Val::new(m, d + 1)),
                        Err(_) => Answer::Tm(goal.clone()),
                    }
                }
                None => Answer::Tm(goal.clone()),
            };
            // a motive of this match: the enclosing arm's goal (if any) must
            // not override it (`dep_match` keeps a branch goal for the nested
            // matches of one compiled pattern)
            let saved_bg = if matches!(answer, Answer::Motive(_)) { s.f.branch_goal.take() } else { None };
            let r = s.match_on(v, &scrut.ty, expanded, &answer, sp, &mut |s, i| {
                let idx = match &expanded[i].body.kind {
                    ExprKind::Lit(Lit::Int(n)) => *n as usize,
                    _ => return internal(sp, "script arm index"),
                };
                let g = s.current_goal(&answer)?;
                s.branch_script(&arms[idx].steps, g, kind.clone(), span)
            });
            if matches!(answer, Answer::Motive(_)) {
                s.f.branch_goal = saved_bg;
            }
            r
        })
    }

    /// The goal generalized over the syntactic occurrences of a scrutinee
    /// term (`scrut`, at the current depth, of HIR type `ty`): the motive of
    /// a script `match`/`if` on a non-variable scrutinee, so each arm's goal
    /// is the goal at the arm's pattern ([`super::tm::abstract_syntactic`];
    /// branch goals are built by substitution, never by quoting values).
    /// `None` if the scrutinee does not occur in the goal term or the
    /// generalized goal is ill-typed (the goal is then kept unchanged and
    /// the arms get the path equation only).
    fn syntactic_motive(&mut self, goal: &Val, scrut: &Tm, ty: &Ty, sp: Span) -> Option<Val> {
        let d = self.depth();
        if matches!(&**scrut, Term::Lit { .. } | Term::Ctor { .. }) {
            return None;
        }
        let gt = goal.at(d);
        let m = match super::tm::abstract_syntactic(&self.env, &gt, scrut) {
            Some(m) => m,
            // the scrutinee spelled out where the goal names a part of it
            // (a `let` of the unfolded body): the goal with its lets put in
            None => {
                let z = super::tm::simp_redexes(&super::tm::zeta_relevant(&gt));
                if crate::auto::meter::term_size(&z, 200_001) > 200_000 {
                    return None;
                }
                super::tm::abstract_syntactic(&self.env, &z, scrut)?
            }
        };
        let dty = self.ty(ty, sp).ok()?;
        let dv = self.eval(&dty).ok()?;
        let saved = self.f.scope.clone();
        self.push_v("y", Rel::Rel, dv);
        let mut b = self.budget();
        let ok = matches!(self.env.infer(&self.f.scope.ctx, &m, &mut b), Ok(t) if matches!(&*t, Value::Sort(_)));
        self.f.scope = saved;
        ok.then(|| Val::new(m, d + 1))
    }

    /// Whether a scrutinee is a variable whose occurrences can be
    /// generalized (a non-let binder).
    fn refinable(&self, scrut: &Expr) -> Option<u32> {
        let ExprKind::Local(l) = &Elab::peel(scrut).kind else { return None };
        let lvl = self.f.scope.local(*l)?;
        let e = self.f.scope.ctx.entries.get(lvl as usize)?;
        if e.def.is_some() {
            return None;
        }
        Some(lvl)
    }

    /// The goal of the current branch of a dependent match with `answer`.
    pub fn current_goal(&mut self, answer: &Answer) -> R<Val> {
        let d = self.depth();
        match answer {
            Answer::Tm(v) => Ok(Val::new(v.at(d), d)),
            Answer::Motive(_) => match &self.f.branch_goal {
                Some(g) => Ok(g.clone()),
                None => internal(self.f.span, "refined goal missing"),
            },
            Answer::Ty(_) | Answer::Prop => internal(self.f.span, "a script branch needs a goal"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn script_if(&mut self, cond: &'a Expr, then: &'a [ScriptStmt], els: &'a [ScriptStmt], goal: Val, kind: ObligationKind, span: Span, sp: Span) -> R<Tm> {
        // a variable condition: refine the goal and the dependent facts
        if self.refinable_var(cond).is_some() {
            let t = self.arena_pat(Pat { kind: PatKind::Lit(Lit::Bool(true)), ty: Ty::Bool, span: sp });
            let w = self.arena_pat(Pat { kind: PatKind::Wild, ty: Ty::Bool, span: sp });
            if let Some(r) = self.refine_match(cond, &[t, w], &[then, els], &goal, &kind, span) {
                return r;
            }
        }
        let refine = self.refinable(cond);
        self.expr(cond, &mut |s, vc| {
            let d = s.depth();
            let c = vc.at(d);
            let answer = match refine {
                _ if let Some(m) = s.syntactic_motive(&goal, &c, &Ty::Bool, sp) => Answer::Motive(m),
                Some(_) => {
                    let gv = s.eval(&goal.at(d))?;
                    let cv = s.eval(&c)?;
                    let mut b = s.budget();
                    match super::basic::abstract_all(&s.env, &s.f.scope.ctx, &gv, &cv, &mut b) {
                        Ok(m) => Answer::Motive(Val::new(m, d + 1)),
                        Err(_) => Answer::Tm(goal.clone()),
                    }
                }
                None => Answer::Tm(goal.clone()),
            };
            let saved_bg = if matches!(answer, Answer::Motive(_)) { s.f.branch_goal.take() } else { None };
            let r = s.if_then_else(c, &answer, sp, &mut |s, b| {
                let g = s.current_goal(&answer)?;
                s.branch_script(if b { then } else { els }, g, kind.clone(), span)
            });
            if matches!(answer, Answer::Motive(_)) {
                s.f.branch_goal = saved_bg;
            }
            r
        })
    }

    /// `cases(k in a..b) { steps }` (§4.4): range facts, `k ≤ v` tests,
    /// goal rewritten with `k = v` in each case.
    #[allow(clippy::too_many_arguments)]
    fn cases(&mut self, var: LocalId, lo: &'a Expr, hi: &'a Expr, inclusive: bool, body: &'a [ScriptStmt], goal: Val, kind: ObligationKind, span: Span, sp: Span) -> R<Tm> {
        let lo_t = self.pure_expr(lo)?;
        let hi_t = self.pure_expr(hi)?;
        let lit = |me: &Self, t: &Tm| -> Option<num_bigint::BigInt> {
            match &*me.eval(t).ok()? {
                Value::Lit { n, .. } => Some(n.clone()),
                _ => None,
            }
        };
        let (Some(a), Some(bnd)) = (lit(self, &lo_t), lit(self, &hi_t)) else { return unsupported(sp, "`cases` bounds must evaluate to literals") };
        let last = if inclusive { bnd.clone() } else { bnd.clone() - 1 };
        let count = &last - &a + 1;
        if count > num_bigint::BigInt::from(256) || count < num_bigint::BigInt::from(1) {
            return unsupported(sp, "`cases` enumerates 1 to 256 values");
        }
        let w = self.width_of(&self.local_decl(var).ty.clone(), sp)?;
        let x = self.local_tm(var, sp)?;
        let relevant = self.f.mode == Mode::Proof;
        let lo_f = self.holds(mk::prim(PrimOp::Le(w), vec![mk::lit(w, a.clone()), x.clone()], vec![]));
        let p_lo = self.prove(ObligationKind::Assert, sp, &lo_f, relevant)?;
        let hi_f = self.holds(mk::prim(PrimOp::Le(w), vec![x.clone(), mk::lit(w, last.clone())], vec![]));
        let p_hi = self.prove(ObligationKind::Assert, sp, &hi_f, relevant)?;
        let values: Vec<num_bigint::BigInt> = {
            let mut v = Vec::new();
            let mut c = a.clone();
            while c <= last {
                v.push(c.clone());
                c += 1;
            }
            v
        };
        self.fact_in("h_lo", lo_f, p_lo, FactOrigin::Assert, sp, &mut |s| {
            let hf = s.holds(mk::prim(PrimOp::Le(w), vec![s.local_tm(var, sp).unwrap(), mk::lit(w, last.clone())], vec![]));
            let php = shift(&p_hi, 1);
            s.fact_in("h_hi", hf, php, FactOrigin::Assert, sp, &mut |s| s.case_chain(var, w, &values, 0, body, goal.clone(), kind.clone(), span, sp))
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn case_chain(&mut self, var: LocalId, w: Width, values: &[num_bigint::BigInt], i: usize, body: &'a [ScriptStmt], goal: Val, kind: ObligationKind, span: Span, sp: Span) -> R<Tm> {
        let Some(v) = values.get(i) else {
            // contradictory: k > last
            let empty = mk::ind(self.p.empty, vec![]);
            let p = self.prove(ObligationKind::Unreachable, sp, &empty, false)?;
            let g = goal.at(self.depth());
            return Ok(Rc::new(Term::Absurd { ty: g, proof: p }));
        };
        let x = self.local_tm(var, sp)?;
        let test = mk::prim(PrimOp::Le(w), vec![x, mk::lit(w, v.clone())], vec![]);
        let answer = Answer::Tm(goal.clone());
        let v = v.clone();
        self.if_then_else(test, &answer, sp, &mut |s, b| {
            if !b {
                return s.case_chain(var, w, values, i + 1, body, goal.clone(), kind.clone(), span, sp);
            }
            // k = v, then rewrite the goal
            let d = s.depth();
            let x = s.local_tm(var, sp)?;
            let eq_t = mk::eq(mk::int_ty(w), x.clone(), mk::lit(w, v.clone()));
            let relevant = s.f.mode == Mode::Proof;
            let p_eq = s.prove(ObligationKind::Assert, sp, &eq_t, relevant)?;
            let gv = s.eval(&goal.at(d))?;
            let xv = s.eval(&x)?;
            let mut bb = s.budget();
            let m = super::basic::abstract_all(&s.env, &s.f.scope.ctx, &gv, &xv, &mut bb).map_err(|e| ElabError { span: sp, msg: format!("`cases`: {e}"), kind: ErrKind::Unsupported })?;
            let litv = s.eval(&mk::lit(w, v.clone()))?;
            let mut env = (*s.f.scope.venv.0).clone();
            env.push(EnvEntry::Rel(litv));
            let ng = s.eval_in(&VEnv(Rc::new(env)), &m)?;
            let ngt = s.quote(&ng, None);
            let p = s.script(body, Val::new(ngt, d), kind.clone(), span)?;
            let wt = mk::int_ty(w);
            let sym = mk::apps(mk::global(s.p.g("eq::sym")), [(Rel::Rel, wt.clone()), (Rel::Rel, x.clone()), (Rel::Rel, mk::lit(w, v.clone())), (Rel::Rel, p_eq)]);
            Ok(Rc::new(Term::Transport { ty: wt, lhs: mk::lit(w, v.clone()), rhs: x, eq: sym, motive: m, val: p }))
        })
    }
}

/// `t` (a term at depth `d`) with the variable of level `lvl` generalized:
/// a term at depth `d + 1` whose `Var(0)` stands for it.
pub(super) fn abstract_level(t: &Tm, d: u32, lvl: u32) -> Tm {
    super::tm::map_post(t, 0, &mut |n, b| match &*n {
        Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= b && d - 1 - (*i - b) == lvl => Some(Rc::new(Term::Var(sandblaster_kernel::term::Idx(b)))),
        Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= b => Some(Rc::new(Term::Var(sandblaster_kernel::term::Idx(*i + 1)))),
        _ => Some(n),
    })
    .expect("abstract_level")
}

/// Whether a script applies `id` (induction).
fn script_recursive(steps: &[ScriptStmt], id: ItemId) -> bool {
    let mut v = Vec::new();
    collect_apps(steps, id, &mut v);
    !v.is_empty()
}

fn collect_apps<'x>(steps: &'x [ScriptStmt], id: ItemId, out: &mut Vec<&'x [Expr]>) {
    for s in steps {
        match &s.kind {
            ScriptKind::Apply { app, .. } | ScriptKind::Exact(app) | ScriptKind::Rewrite { eq: app, .. } => {
                if let ExprKind::Call { callee: Callee::Item(c, _), args } = &app.kind
                    && *c == id
                {
                    out.push(args);
                }
            }
            ScriptKind::Assert { steps: Some(ss), .. } => collect_apps(ss, id, out),
            ScriptKind::Match { arms, .. } => arms.iter().for_each(|a| collect_apps(&a.steps, id, out)),
            ScriptKind::If { then, els, .. } => {
                collect_apps(then, id, out);
                collect_apps(els, id, out);
            }
            ScriptKind::Cases { steps, .. } => collect_apps(steps, id, out),
            ScriptKind::Calc { links, .. } => links.iter().filter_map(|l| l.steps.as_ref()).for_each(|ss| collect_apps(ss, id, out)),
            _ => {}
        }
    }
}

fn collect_script_rest(steps: &[ScriptStmt], out: &mut std::collections::HashMap<LocalId, LocalId>) {
    fn pat_rest(p: &Pat, scrut: LocalId, out: &mut std::collections::HashMap<LocalId, LocalId>) {
        match &p.kind {
            PatKind::Deref { pat, .. } => pat_rest(pat, scrut, out),
            PatKind::Slice { prefix, rest: Some(Some(r)), suffix } if prefix.len() + suffix.len() >= 1 => {
                if let PatKind::Binding { local, .. } = &r.kind {
                    out.insert(*local, scrut);
                }
            }
            _ => {}
        }
    }
    for s in steps {
        match &s.kind {
            ScriptKind::Match { scrut, arms } => {
                // a local, or a tuple of locals matched by tuple patterns
                let scruts = super::recursive::scrut_locals(scrut);
                for a in arms {
                    match (&a.pat.kind, scruts.as_slice()) {
                        (_, [Some(x)]) => pat_rest(&a.pat, *x, out),
                        (PatKind::Tuple(ps), _) if ps.len() == scruts.len() => {
                            for (p, x) in ps.iter().zip(&scruts) {
                                if let Some(x) = x {
                                    pat_rest(p, *x, out);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                for a in arms {
                    collect_script_rest(&a.steps, out);
                }
            }
            ScriptKind::If { then, els, .. } => {
                collect_script_rest(then, out);
                collect_script_rest(els, out);
            }
            ScriptKind::Assert { steps: Some(ss), .. } | ScriptKind::Cases { steps: ss, .. } => collect_script_rest(ss, out),
            ScriptKind::Calc { links, .. } => links.iter().filter_map(|l| l.steps.as_ref()).for_each(|ss| collect_script_rest(ss, out)),
            _ => {}
        }
    }
}

/// The first application `g a₁..aₙ` (exactly `arity` arguments) in `t`
/// whose arguments are closed in the term's context.
fn find_app(t: &Tm, g: sandblaster_kernel::term::GlobalId, arity: usize) -> Option<Tm> {
    let (h, args) = super::items::spine(t);
    if let Term::Global(x) = &*h
        && *x == g
        && args.len() == arity
    {
        return Some(t.clone());
    }
    match &**t {
        Term::App { fun, arg, .. } => find_app(fun, g, arity).or_else(|| find_app(arg, g, arity)),
        Term::Eq { lhs, rhs, ty } => find_app(lhs, g, arity).or_else(|| find_app(rhs, g, arity)).or_else(|| find_app(ty, g, arity)),
        Term::Prim { args, .. } => args.iter().find_map(|a| find_app(a, g, arity)),
        Term::Ctor { args, .. } => args.iter().find_map(|a| find_app(a, g, arity)),
        Term::Fst(x) | Term::Snd(x) => find_app(x, g, arity),
        Term::Match { scrut, .. } => find_app(scrut, g, arity),
        Term::Pair { fst, snd, .. } => find_app(fst, g, arity).or_else(|| find_app(snd, g, arity)),
        _ => None,
    }
}

/// The applications of `g` written in the goal's logical structure: in each
/// conjunct of a `&&` goal (a later conjunct sits under the proof of the
/// earlier ones; an application there that does not mention it), in the
/// sides of an `||` / `Or`, and as [`find_app`] finds them in an atom (not in
/// the arms of a boolean `&&` or `if`: those stay folded).
fn prop_apps(t: &Tm, g: sandblaster_kernel::term::GlobalId, arity: usize) -> Vec<Tm> {
    fn go(t: &Tm, g: sandblaster_kernel::term::GlobalId, arity: usize, out: &mut Vec<Tm>, fuel: &mut u32) {
        if *fuel == 0 || out.len() >= 8 {
            return;
        }
        *fuel -= 1;
        match &**t {
            Term::Sigma { fst, snd, .. } => {
                go(fst, g, arity, out, fuel);
                let mut inner = Vec::new();
                go(snd, g, arity, &mut inner, fuel);
                for a in inner {
                    if !super::tm::any_node_depth(&a, &mut |m, k| matches!(m, Term::Var(sandblaster_kernel::term::Idx(i)) if *i == k)) {
                        out.push(sandblaster_kernel::util::shift(&a, -1));
                    }
                }
            }
            Term::Ind { params, .. } => params.iter().for_each(|a| go(a, g, arity, out, fuel)),
            _ => {
                if let Some(a) = find_app(t, g, arity) {
                    out.push(a);
                }
            }
        }
    }
    let mut out = Vec::new();
    go(t, g, arity, &mut out, &mut 64);
    out
}

/// The first of [`prop_apps`].
fn find_app_prop(t: &Tm, g: sandblaster_kernel::term::GlobalId, arity: usize) -> Option<Tm> {
    prop_apps(t, g, arity).into_iter().next()
}

/// An application of `g` under the binders of `t` (match arms, `let`
/// bodies, `λ`s: the unfolded body of an exec function, whose calls sit in
/// the arms of its tests) that mentions none of those binders, as a term at
/// `t`'s depth.
fn find_app_under(t: &Tm, g: sandblaster_kernel::term::GlobalId, arity: usize) -> Option<Tm> {
    fn go(t: &Tm, b: u32, g: sandblaster_kernel::term::GlobalId, arity: usize, seen: &mut std::collections::HashSet<(*const Term, u32)>, out: &mut Option<Tm>) {
        if out.is_some() || !seen.insert((Rc::as_ptr(t), b)) {
            return;
        }
        if b > 0 {
            let (h, args) = super::items::spine(t);
            if matches!(&*h, Term::Global(x) if *x == g) && args.len() == arity && !super::tm::any_node_depth(t, &mut |m, k| matches!(m, Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= k && *i - k < b)) {
                *out = Some(sandblaster_kernel::util::shift(t, -(b as i64)));
                return;
            }
        }
        super::tm::children_depth(t, &mut |c, k| go(c, b + k, g, arity, seen, out));
    }
    let mut out = None;
    go(t, 0, g, arity, &mut std::collections::HashSet::new(), &mut out);
    out
}

/// What was left without a closing statement ([`Elab::close_implicit`]).
#[derive(Clone, Copy)]
pub(super) enum OpenEnd {
    /// A block that ends after other statements.
    Block,
    /// A `calc!` link without `by { .. }`.
    CalcLink,
}

/// The first irrelevant `let` of a goal term (pre-order) whose type and
/// value mention no binder of the goal itself: its name, type and value as
/// terms of the goal's context (see `Elab::hoist_facts`), among the `let`s
/// whose value satisfies `pick`.
fn find_hoistable_by(t: &Tm, pick: &dyn Fn(&Tm) -> bool) -> Option<(String, Tm, Tm)> {
    fn closed_above(t: &Tm, k: u32) -> bool {
        !super::tm::any_node_depth(t, &mut |n, b| matches!(n, Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= b && *i < b + k))
    }
    let mut out = None;
    let mut seen = std::collections::HashSet::new();
    fn go(t: &Tm, k: u32, out: &mut Option<(String, Tm, Tm)>, seen: &mut std::collections::HashSet<(*const Term, u32)>, pick: &dyn Fn(&Tm) -> bool) {
        if out.is_some() || !seen.insert((Rc::as_ptr(t), k)) {
            return;
        }
        if let Term::Let { name, rel: Rel::Irr, ty, val, .. } = &**t
            && pick(val)
            && closed_above(ty, k)
            && closed_above(val, k)
        {
            *out = Some((name.to_string(), sandblaster_kernel::util::shift(ty, -(k as i64)), sandblaster_kernel::util::shift(val, -(k as i64))));
            return;
        }
        super::tm::children_depth(t, &mut |c, b| go(c, k + b, out, seen, pick));
    }
    go(t, 0, &mut out, &mut seen, pick);
    out
}

/// The goal term (at depth `d`) as a term at depth `d + 1`, the first
/// hoistable `let` (as found by [`find_hoistable_by`] with `pick`)
/// removed: its variable becomes the new outer binder.
fn hoist_one_by(t: &Tm, pick: &dyn Fn(&Tm) -> bool) -> Tm {
    fn closed_above(t: &Tm, k: u32) -> bool {
        !super::tm::any_node_depth(t, &mut |n, b| matches!(n, Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= b && *i < b + k))
    }
    fn go(t: &Tm, k: u32, done: &mut bool, memo: &mut std::collections::HashMap<(*const Term, u32), Tm>, pick: &dyn Fn(&Tm) -> bool) -> Tm {
        if *done {
            // the rest only needs the context shift
            return super::tm::map_post(t, 0, &mut |n, b| match &*n {
                Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= b + k => Some(Rc::new(Term::Var(sandblaster_kernel::term::Idx(i + 1)))),
                _ => Some(n),
            })
            .unwrap_or_else(|| t.clone());
        }
        if let Some(r) = memo.get(&(Rc::as_ptr(t), k)) {
            return r.clone();
        }
        let r = match &**t {
            Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= k => Rc::new(Term::Var(sandblaster_kernel::term::Idx(i + 1))),
            Term::Let { rel: Rel::Irr, ty, val, body, .. } if pick(val) && closed_above(ty, k) && closed_above(val, k) => {
                *done = true;
                let b2 = go(body, k + 1, done, memo, pick);
                super::tm::subst0(&b2, &Rc::new(Term::Var(sandblaster_kernel::term::Idx(k))))
            }
            _ => super::tm::rebuild(t, &mut |c, b| go(c, k + b, done, memo, pick)),
        };
        memo.insert((Rc::as_ptr(t), k), r.clone());
        r
    }
    go(t, 0, &mut false, &mut std::collections::HashMap::new(), pick)
}

