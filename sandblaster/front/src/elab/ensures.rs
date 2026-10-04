//! `f::ensures` (DESIGN.md §7.3): `Π(T..)(x..)(h : P..). Q[x, f x h]`
//! (hypotheses relevant), proven by walking the body of `f`: every
//! `let`, dependent match and plain match of the body is mirrored in the
//! proof (the motive of a mirrored dependent match is `Π(e : Eq(D, s, y)).
//! Q[x, M(y) e]` where `M(y)` is the body's match on `y`), so at each tail
//! value `v` the prover proves `Q[x, v]` in that branch's context (path
//! equations and facts as binders). Recursive `f` starts with `delta`
//! (§5.6); recursive calls are measure-recursive calls of `f::ensures`
//! (their facts are the induction hypotheses).
//!
//! The walk itself ([`Elab::walk_body`]) is shared with the post-loop
//! lemmas `f::loop#k::ensures` (DESIGN.md §7.4, `loops.rs`): a [`WalkGoal`]
//! says what the goal is at a value and how a tail value is proven.

use std::rc::Rc;

use sandblaster_kernel::term::{DefKind, GlobalId, Recursion, Rel, Term, Tm};
use sandblaster_kernel::util::{mk, shift, shift_from};

use super::items::{lam_tele, pi_tele};
use super::{Elab, FnState, Mode, R};
use crate::hir::*;
use crate::prover::{FactOrigin, ObligationKind};
use crate::span::Span;

/// What a body walk proves ([`Elab::walk_body`]): `f::ensures` (§7.3) and
/// the post-loop lemmas `f::loop#k::ensures` (§7.4) mirror a committed body
/// the same way and differ only in the goal at a value and in how the goal
/// is proven at a tail value.
pub(super) trait WalkGoal<'a> {
    /// The goal for the value `v`, a term at the current depth.
    fn goal(&mut self, el: &mut Elab<'a>, v: &Tm) -> R<Tm>;
    /// A proof of `goal(v)` for the tail value `v`, in the current context.
    fn leaf(&mut self, el: &mut Elab<'a>, v: &Tm) -> R<Tm>;
    /// Whether a plain match on a single-constructor value (a projection
    /// of a struct or tuple) is mirrored with the path equation `s = C(f̄)`
    /// as a fact, so hypotheses about the projections of `s` (a
    /// refinement's representation relation, DESIGN.md §15.3) meet the
    /// field binders. Off for `ensures` and the post-loop lemmas.
    fn eq_on_projections(&self) -> bool {
        false
    }
    /// Whether a getter's tail projection of a *variable* (`self.0`
    /// returned as is: a plain match on a single-constructor value that is
    /// a binder of the context, whose arm is one of its field binders) is
    /// mirrored with its path equation `s = C(f̄)`, so that a goal about `s`
    /// (`ret == self.0`) meets the field binder the arm returns. On for
    /// `ensures`: without it a getter's contract names a field binder the
    /// goal cannot relate to `s`. (Only for that shape: an arm that goes on
    /// computing keeps its facts about `s` as they are.)
    fn eq_on_var_projections(&self) -> bool {
        false
    }
    /// Whether the walk splits a match on `scrut` (a term at the current
    /// depth); otherwise the match is a tail value. Always, except for the
    /// value walks of a lockstep (`elab::refines`), which split the choices
    /// of a body, not the data it is given.
    fn splits(&self, _scrut: &Tm) -> bool {
        true
    }
    /// Whether every plain match is mirrored with its path equation (not
    /// only single-constructor ones): the value walks of a lockstep, whose
    /// matches on a variable (`match found { .. }` of a view) must tell the
    /// goal's other occurrences of it which constructor it is.
    fn eq_on_all(&self) -> bool {
        false
    }
    /// At the entry of an arm of a split match (its path equation just
    /// pushed): a proof of `Empty` when the arm is impossible — its path
    /// equation contradicts the facts in scope — so the arm is closed by
    /// `absurd` instead of walked. Never, except for the lockstep's walks of
    /// a target body and of a choice (`elab::lockstep`), whose arms meet the
    /// code's path equations.
    fn prune(&mut self, _el: &mut Elab<'a>) -> R<Option<Tm>> {
        Ok(None)
    }
    /// Entering (`true`) or leaving an arm of a split match (the lockstep
    /// keeps the branch conditions for its report).
    fn arm(&mut self, _el: &mut Elab<'a>, _enter: bool) {}
}

/// The goal of `f::ensures`: `Q[ret := v]`, proven by the prover at every
/// tail (with the induction hypotheses of the recursive calls in it).
struct EnsGoal<'a> {
    /// The `ensures`; `None` for the implicit Nat range of the result
    /// ([`Elab::nat_range_def`]).
    en: Option<&'a Ensures>,
    /// The result's type (for the Nat range).
    ret: &'a Ty,
    /// The return type, at depth `base`.
    ret_ty: Tm,
    base: u32,
    span: Span,
}

impl<'a> WalkGoal<'a> for EnsGoal<'a> {
    fn eq_on_var_projections(&self) -> bool {
        true
    }

    fn goal(&mut self, el: &mut Elab<'a>, v: &Tm) -> R<Tm> {
        let rt = shift(&self.ret_ty, (el.depth() - self.base) as i64);
        match self.en {
            Some(en) => el.ensures_prop(en, &rt, v.clone(), self.span),
            None => el.nat_range_prop(self.ret, v.clone(), self.span),
        }
    }

    fn leaf(&mut self, el: &mut Elab<'a>, t: &Tm) -> R<Tm> {
        let d0 = el.depth();
        let (en, ret, ret_ty, base, span) = (self.en, self.ret, self.ret_ty.clone(), self.base, self.span);
        let t0 = t.clone();
        el.with_induction_hyps(t, &mut |s| {
            let d = s.depth();
            let (t, rt) = (shift(&t0, (d - d0) as i64), shift(&ret_ty, (d - base) as i64));
            let goal = match en {
                Some(en) => s.ensures_prop(en, &rt, t, span)?,
                None => s.nat_range_prop(ret, t, span)?,
            };
            s.with_callee_contracts(&goal, span, &mut |s, g| s.prove_relevant(ObligationKind::Ensures, span, g))
        })
    }
}

/// At most this many callee contracts per contract goal
/// ([`Elab::with_callee_contracts`]).
const CALLEE_CONTRACTS_MAX: usize = 8;

impl<'a> Elab<'a> {
    /// The contracts of the calls a contract statement writes (`goal`, a
    /// term at the current depth): for each full application `g a…` in it
    /// of an opaque function (callers know it by its contract: `opaque()`,
    /// §5.6) with a checked `g::ensures`, the instance `g::ensures a… :
    /// Q[a…, g a…]` is an irrelevant fact of `k`'s proof of the goal — a
    /// call in a statement brings its callee's contract as a call in a body
    /// does (DESIGN.md §7.3), so a contract may name an opaque function
    /// (an opaque constructor `Position::new(x)`) whose value only its own
    /// contract states. A transparent callee needs none: evaluation unfolds
    /// it. Calls under the statement's binders count when they do not use
    /// them. At most [`CALLEE_CONTRACTS_MAX`].
    pub(super) fn with_callee_contracts(&mut self, goal: &Tm, span: Span, k: &mut dyn FnMut(&mut Elab<'a>, &Tm) -> R<Tm>) -> R<Tm> {
        let insts = self.callee_contract_instances(goal);
        if insts.is_empty() {
            return k(self, goal);
        }
        let saved = self.f.scope.clone();
        let n = insts.len() as i64;
        let r = (|| -> R<Tm> {
            for (i, (eg, ty, pf)) in insts.iter().enumerate() {
                let (ty, pf) = (shift(ty, i as i64), shift(pf, i as i64));
                self.push_fact_rel("h_ens", Rel::Irr, &ty, Some(&pf), FactOrigin::CalleeEnsures(*eg), span)?;
            }
            k(self, &shift(goal, n))
        })();
        self.f.scope = saved;
        let mut body = r?;
        for (i, (_, ty, pf)) in insts.iter().enumerate().rev() {
            body = mk::let_("h_ens", Rel::Irr, shift(ty, i as i64), shift(pf, i as i64), body);
        }
        Ok(body)
    }

    /// The callee contract instances of [`Elab::with_callee_contracts`]:
    /// `(g::ensures, statement, proof)`, terms at the current depth.
    fn callee_contract_instances(&self, goal: &Tm) -> Vec<(GlobalId, Tm, Tm)> {
        let mut calls: Vec<Tm> = Vec::new();
        fn walk(t: &Tm, depth: u32, out: &mut Vec<Tm>, budget: &mut u32) {
            if *budget == 0 {
                return;
            }
            *budget -= 1;
            if let Term::App { .. } = &**t {
                let (h, _) = super::items::spine(t);
                if matches!(&*h, Term::Global(_)) && (0..depth).all(|i| !sandblaster_kernel::util::occurs(t, i)) {
                    out.push(shift(t, -(depth as i64)));
                }
            }
            super::tm::children_depth(t, &mut |c, k| walk(c, depth + k, out, budget));
        }
        let mut budget = 4096;
        walk(goal, 0, &mut calls, &mut budget);
        let mut out: Vec<(GlobalId, Tm, Tm)> = Vec::new();
        for c in calls {
            if out.len() >= CALLEE_CONTRACTS_MAX {
                break;
            }
            let (h, args) = super::items::spine(&c);
            let Term::Global(g) = &*h else { continue };
            // a transparent callee's value is its body (evaluation sees it);
            // an opaque one is known by its contract only
            if self.env.global_opaque(*g) != Some(true) {
                continue;
            }
            let Some(name) = self.env.global_name(*g) else { continue };
            let ens = format!("{name}::ensures");
            if !self.defs.iter().any(|d| d.name == ens && d.status == super::DefStatus::Checked) {
                continue;
            }
            let Some(eg) = self.env.lookup_global(&ens) else { continue };
            let Some(n) = self.env.global_param_rels(eg).map(|r| r.len()) else { continue };
            if args.len() != n {
                continue;
            }
            let Some(mut t) = self.env.global_type(eg) else { continue };
            let mut ok = true;
            for _ in 0..n {
                let next = match &*t {
                    Term::Pi { cod, .. } => cod.clone(),
                    _ => {
                        ok = false;
                        break;
                    }
                };
                t = next;
            }
            if !ok {
                continue;
            }
            let ty = super::tm::subst_closed(&t, &args);
            if out.iter().any(|(_, t2, _)| self.env.alpha_eq_relevant(t2, &ty, &|a, b| a == b)) {
                continue;
            }
            let proof = mk::apps(mk::global(eg), args.iter().map(|a| (Rel::Rel, a.clone())));
            out.push((eg, ty, proof));
        }
        out
    }
    /// Defines and proves `f::ensures` for the exec function `id` (global
    /// `g`).
    pub fn ensures_def(&mut self, id: ItemId, f: &'a FnDef, g: GlobalId) -> R<()> {
        let Some(en) = &f.ensures else { return Ok(()) };
        self.ensures_def_of(id, f, g, Some(en))
    }

    /// The implicit "Nat range" lemma `f::nat_range : Π(x..)(h..).
    /// R[f x h]` of a spec function whose result type has `Nat` in
    /// covariant positions (the result, tuple and struct components,
    /// `Option` contents; [`Elab::nat_range_prop`]): proven like an
    /// `ensures` (the recursive calls' ranges are induction hypotheses).
    /// `Nat` is `Int` in the kernel; the range is what makes a spec
    /// result usable where a `Nat` is expected (`0 <= f(x)`, a Nat
    /// parameter's guard). Nothing is reported when the proof does not go
    /// through: the function just has no range lemma.
    pub fn nat_range_def(&mut self, id: ItemId, f: &'a FnDef, g: GlobalId) {
        if !self.has_nat_range(&f.ret, 0) {
            return;
        }
        let (no, nd, ndefs) = (self.obligations.len(), self.diags.list.len(), self.defs.len());
        let saved_f = std::mem::replace(&mut self.f, FnState::new(String::new(), None, &[], Span::DUMMY));
        let saved_rec = self.ens_rec.take();
        let r = self.ensures_def_of(id, f, g, None);
        let ok = r.is_ok() && self.obligations[no..].iter().all(|o| o.proven()) && self.defs[ndefs..].iter().all(|d| d.status == super::DefStatus::Checked) && self.defs.len() > ndefs;
        if ok {
            let name = format!("{}::nat_range", self.krate.item(id).path);
            if let (Some(lg), Some(ar)) = (self.env.lookup_global(&name), self.env.global_arity(g)) {
                self.nat_ranges.insert(g, (lg, ar));
            }
        } else if r.is_ok() && self.obligations[no..].iter().all(|o| o.proven()) && self.defs.len() > ndefs {
            // every obligation was proven but the kernel rejected the
            // definition: an internal error of the elaborator, which stays
            // an error (never a silently missing range)
        } else {
            if std::env::var_os("SANDBLASTER_TRACE_NAT_RANGE").is_some() {
                for dg in &self.diags.list[nd..] {
                    eprintln!("nat_range of {}: {} {:?} {:?}", self.krate.item(id).path, dg.msg, dg.goal, dg.notes);
                }
            }
            // the first unproven goal, named where an obligation about the
            // function fails ([`Elab::nat_range_note`])
            let why = match (self.diags.list[nd..].iter().find_map(|dg| dg.goal.clone()), &r) {
                (Some(g), _) => format!("`{}`", g.lines().next().unwrap_or_default().trim_start_matches("goal: ").chars().take(240).collect::<String>()),
                (None, Err(e)) => e.msg.clone(),
                (None, Ok(())) => "a step the prover could not take".into(),
            };
            self.nat_range_missing.insert(g, why);
            self.obligations.truncate(no);
            self.diags.list.truncate(nd);
            self.defs.truncate(ndefs);
        }
        self.f = saved_f;
        self.ens_rec = saved_rec;
    }

    /// The note for a failed obligation whose goal `target` (a term) or a
    /// visible fact applies a spec function that has no Nat range lemma
    /// ([`Elab::nat_range_def`]): which function, and where its range proof
    /// stopped.
    pub(super) fn nat_range_note(&self, target: &Tm) -> Option<String> {
        if self.nat_range_missing.is_empty() {
            return None;
        }
        let mut found: Option<GlobalId> = None;
        let mut scan = |t: &Tm| {
            super::tm::any_node(t, &mut |n| {
                if let Term::Global(g) = n
                    && self.nat_range_missing.contains_key(g)
                {
                    found = Some(*g);
                    return true;
                }
                false
            })
        };
        // the goal first, then the facts in scope (a range-less function in
        // a fact `m(s) == Some(k)` is why `0 <= k` does not follow)
        if !scan(target) {
            let sc = &self.f.scope;
            for fr in &sc.facts {
                if !sc.hidden.contains(&fr.lvl.0)
                    && let Some(t) = sc.fact_tys.get(&fr.lvl.0)
                    && scan(t)
                {
                    break;
                }
            }
        }
        let g = found?;
        let name = self.env.global_name(g).map(|n| n.trim_start_matches("crate::").to_string()).unwrap_or_default();
        Some(format!("`{name}` has no automatic Nat range fact (`0 <= {name}(..)` for its `Nat` components): its proof stopped at {}; state the bound you need as a lemma", self.nat_range_missing[&g]))
    }

    /// The Nat range facts of the applications of spec functions with a
    /// range lemma ([`Elab::nat_range_def`]) in `terms` (terms at depth
    /// `d`, the current one): `(R[f a..], f::nat_range a..)` per distinct
    /// application whose arguments are closed in the current context, at
    /// most `cap`.
    pub(super) fn nat_range_instances(&self, terms: &[Tm], cap: usize) -> Vec<(Tm, Tm)> {
        let d = self.depth();
        let mut out: Vec<(Tm, Tm)> = Vec::new();
        let mut occs: Vec<Tm> = Vec::new();
        let mut seen: std::collections::HashSet<(*const Term, u32)> = std::collections::HashSet::new();
        let mut stack: Vec<(Tm, u32)> = terms.iter().map(|t| (t.clone(), 0)).collect();
        while let Some((t, b)) = stack.pop() {
            if out.len() >= cap || !seen.insert((Rc::as_ptr(&t), b)) {
                continue;
            }
            if let Term::App { .. } = &*t {
                let (h, args) = super::items::spine(&t);
                if let Term::Global(g) = &*h
                    && let Some((lg, ar)) = self.nat_ranges.get(g)
                    && args.len() == *ar as usize
                    && !super::tm::has_erased(&t)
                    && !super::tm::any_node_depth(&t, &mut |n, k| matches!(n, Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= k && *i - k < b))
                {
                    let o = shift(&t, -(b as i64));
                    if !occs.iter().any(|x| self.env.alpha_eq_relevant(x, &o, &|a, c| a == c))
                        && let Some(lty) = self.env.global_type(*lg)
                        && let Some(rels) = self.env.global_param_rels(*lg)
                    {
                        let (_, oargs) = super::items::spine(&o);
                        let stmt = super::tm::subst_closed(&strip_pis(&lty, *ar), &oargs);
                        let pf = mk::apps(mk::global(*lg), rels.iter().copied().zip(oargs.iter().cloned()));
                        occs.push(o);
                        out.push((stmt, pf));
                    }
                }
            }
            super::tm::children_depth(&t, &mut |c, k| stack.push((c.clone(), b + k)));
        }
        let _ = d;
        out
    }

    /// Whether a goal (a term at the current depth) is one linear
    /// arithmetic decides — an integer equation, a comparison, `Empty` —
    /// the goals for which the Nat range facts are bound.
    pub(super) fn arithmetic_goal(&self, target: &Tm) -> bool {
        self.arithmetic_goal_at(target, 0)
    }

    fn arithmetic_goal_at(&self, target: &Tm, depth: u32) -> bool {
        use sandblaster_kernel::term::PrimOp;
        // on the goal term (no evaluation: this runs for every obligation);
        // a match on a constructor (a Nat range at a known value) is
        // contracted first
        let peel = |t: &Tm| {
            let mut t = t.clone();
            while let Term::Let { body, .. } = &*t.clone() {
                t = body.clone();
            }
            t
        };
        let mut t = peel(target);
        if matches!(&*t, Term::Match { scrut, .. } if matches!(&**scrut, Term::Ctor { .. })) {
            t = peel(&super::tm::simp_redexes(&t));
        }
        // a match that keeps the equation of its scrutinee (`match e as y
        // return e == y -> P with ..` applied to `refl(e)`): its arms, past
        // that equation
        if let Term::App { fun, .. } = &*t.clone()
            && matches!(&**fun, Term::Match { .. })
        {
            t = fun.clone();
        }
        let arm_body = |b: &Tm| {
            let mut b = b.clone();
            while let Term::Lam { body, .. } = &*b.clone() {
                b = body.clone();
            }
            b
        };
        match &*t {
            // a proposition that matches on a program value (`match f(n) {
            // Some(k) => k >= 0, None => true }`) whose arms are arithmetic
            Term::Match { scrut, arms, .. } if depth < 4 && !matches!(&**scrut, Term::Ctor { .. }) && !arms.is_empty() => arms.iter().all(|a| {
                let b = arm_body(&a.body);
                self.arithmetic_goal_at(&b, depth + 1) || self.trivial_goal(&b)
            }),
            Term::Eq { ty, lhs, rhs } => match &**ty {
                Term::IntTy(_) => true,
                Term::Ind { ind, .. } if *ind == self.p.bool_ => matches!(&**rhs, Term::Ctor { .. }) && matches!(&**lhs, Term::Prim { op, .. } if matches!(op, PrimOp::Eq(_) | PrimOp::Ne(_) | PrimOp::Lt(_) | PrimOp::Le(_) | PrimOp::Gt(_) | PrimOp::Ge(_))),
                _ => false,
            },
            Term::Sigma { fst, snd, .. } if depth < 4 => self.arithmetic_goal_at(fst, depth + 1) && self.arithmetic_goal_at(snd, depth + 1),
            Term::Ind { ind, .. } => *ind == self.p.empty,
            _ => false,
        }
    }

    /// Whether a goal (a term at the current depth) tests `0 <= t` somewhere
    /// for a `t` that applies a spec function with a Nat range lemma: the
    /// guard of a `Nat` parameter (`below(r, cap(f, m))` unfolds to a match
    /// on `0 <= cap(f, m)`), which the range decides.
    pub(super) fn ranged_guard_goal(&self, target: &Tm) -> bool {
        use sandblaster_kernel::term::PrimOp;
        if self.nat_ranges.is_empty() {
            return false;
        }
        super::tm::any_node(target, &mut |n| match n {
            Term::Prim { op: PrimOp::Le(sandblaster_kernel::term::Width::Int), args, .. } if args.len() == 2 => {
                matches!(&*args[0], Term::Lit { n, .. } if *n == 0.into()) && super::tm::any_node(&args[1], &mut |m| matches!(m, Term::Global(g) if self.nat_ranges.contains_key(g)))
            }
            _ => false,
        })
    }

    /// Whether a goal (a term) is a conjunction of lower bounds `0 <= t` /
    /// `t >= 0` (called when range facts are available): what the range
    /// facts are for, so they are bound from the first attempt.
    pub(super) fn range_goal(&self, target: &Tm) -> bool {
        use sandblaster_kernel::term::PrimOp;
        let mut t = target.clone();
        while let Term::Let { body, .. } = &*t.clone() {
            t = body.clone();
        }
        // (any `t`: a lower bound is what a Nat range gives, also of a value
        // bound by a pattern of a ranged function's result — the `0 <= y`
        // a `Nat` parameter requires of `Some((y, s)) = groups(..)`)
        let applies_ranged = |_: &Tm| true;
        match &*t {
            Term::Sigma { fst, snd, .. } => self.range_goal(fst) && self.range_goal(&shift(snd, -1)),
            Term::Eq { lhs, rhs, .. } if matches!(&**rhs, Term::Ctor { ctor: 1, .. }) => match &**lhs {
                Term::Prim { op: PrimOp::Le(_), args, .. } => matches!(&*args[0], Term::Lit { n, .. } if *n == 0.into()) && applies_ranged(&args[1]),
                Term::Prim { op: PrimOp::Ge(_), args, .. } => matches!(&*args[1], Term::Lit { n, .. } if *n == 0.into()) && applies_ranged(&args[0]),
                _ => false,
            },
            _ => false,
        }
    }

    /// `true == true`, `()`: an arm with nothing to prove.
    fn trivial_goal(&self, t: &Tm) -> bool {
        match &**t {
            Term::Eq { lhs, rhs, .. } => matches!((&**lhs, &**rhs), (Term::Ctor { ctor: a, .. }, Term::Ctor { ctor: b, .. }) if a == b),
            Term::Ind { ind, .. } => *ind == self.p.unit,
            _ => false,
        }
    }

    /// Whether a type has `Nat` in covariant positions (see
    /// [`Elab::nat_range_prop`]).
    fn has_nat_range(&self, ty: &Ty, depth: u32) -> bool {
        if depth > 3 {
            return false;
        }
        match ty.peel_refs() {
            Ty::Nat => true,
            Ty::Tuple(ts) => ts.iter().any(|t| self.has_nat_range(t, depth + 1)),
            Ty::Option(t) => self.has_nat_range(t, depth + 1),
            Ty::Adt(id, args) => match &self.krate.item(*id).kind {
                ItemKind::Struct(sd) => sd.fields.iter().any(|fd| self.has_nat_range(&fd.ty.subst(args), depth + 1)),
                // an enum's variant fields (the lift's `Result<Nat, E>`),
                // like `Option`'s `Some`
                ItemKind::Enum(ed) => ed.variants.iter().any(|v| v.fields.iter().any(|fd| self.has_nat_range(&fd.ty.subst(args), depth + 1))),
                _ => false,
            },
            _ => false,
        }
    }

    /// The Nat range of a value `t` (a term at the current depth) of type
    /// `ty`: `0 <= t` for a `Nat`; the conjunction of the components' for a
    /// tuple or struct (by projection, the terms field accesses elaborate
    /// to); `match t { None => (), Some(v) => R[v] }` for an `Option`;
    /// `()` otherwise.
    pub(super) fn nat_range_prop(&mut self, ty: &Ty, t: Tm, span: Span) -> R<Tm> {
        Ok(self.nat_range_opt(ty, t, span, 0)?.unwrap_or_else(|| mk::ind(self.p.unit, vec![])))
    }

    fn nat_range_opt(&mut self, ty: &Ty, t: Tm, span: Span, depth: u32) -> R<Option<Tm>> {
        if depth > 3 || !self.has_nat_range(ty, 0) {
            return Ok(None);
        }
        let conj = |parts: Vec<Tm>| -> Option<Tm> {
            let mut it = parts.into_iter().rev();
            let mut acc = it.next()?;
            for p in it {
                acc = mk::sigma("h", Rel::Rel, p, shift(&acc, 1));
            }
            Some(acc)
        };
        match ty.peel_refs() {
            Ty::Nat => Ok(Some(self.holds(mk::prim(sandblaster_kernel::term::PrimOp::Le(sandblaster_kernel::term::Width::Int), vec![mk::lit(sandblaster_kernel::term::Width::Int, 0u8), t], vec![])))),
            Ty::Tuple(ts) => {
                let (ind, params) = self.ind_of(ty, span)?;
                let mut parts = Vec::new();
                for (i, c) in ts.iter().enumerate() {
                    let fty = self.ty(c, span)?;
                    let comp = self.proj(ind, params.clone(), t.clone(), i, ts.len(), fty);
                    if let Some(p) = self.nat_range_opt(c, comp, span, depth + 1)? {
                        parts.push(p);
                    }
                }
                Ok(conj(parts))
            }
            Ty::Adt(id, args) if matches!(&self.krate.item(*id).kind, ItemKind::Enum(_)) => {
                // `match t { V_i(f..) => R[f..], .. }`: each variant's fields'
                // ranges (`()` for a variant without `Nat`), like `Option`
                let ItemKind::Enum(ed) = &self.krate.item(*id).kind else { return Ok(None) };
                let (ind, params) = self.ind_of(ty, span)?;
                let Some(decl) = self.env.inductive_decl(ind) else { return Ok(None) };
                if decl.ctors.len() != ed.variants.len() {
                    return Ok(None);
                }
                let unit = mk::ind(self.p.unit, vec![]);
                let mut arms = Vec::new();
                for (v, c) in ed.variants.iter().zip(decl.ctors.iter()) {
                    // only plain variants: every kernel field is a HIR field
                    if c.fields.len() != v.fields.len() || c.fields.iter().any(|(_, r, _)| *r != Rel::Rel) {
                        return Ok(None);
                    }
                    let saved = self.f.scope.clone();
                    let r = (|| -> R<Tm> {
                        let mut lvls = Vec::new();
                        for fd in &v.fields {
                            let fh = fd.ty.subst(args);
                            let fty = self.ty(&fh, span)?;
                            lvls.push((self.push("f", Rel::Rel, &fty, None)?, fh));
                        }
                        let mut parts = Vec::new();
                        for (lvl, fh) in &lvls {
                            let fv = self.f.scope.var(*lvl);
                            if let Some(p) = self.nat_range_opt(fh, fv, span, depth + 1)? {
                                parts.push(p);
                            }
                        }
                        Ok(conj(parts).unwrap_or_else(|| unit.clone()))
                    })();
                    self.f.scope = saved;
                    let names: Vec<sandblaster_kernel::term::Name> = v.fields.iter().map(|_| Rc::from("f")).collect();
                    arms.push(sandblaster_kernel::term::Arm { names, body: r? });
                }
                Ok(Some(Rc::new(Term::Match { ind, params, scrut: t, motive: mk::ty(), arms })))
            }
            Ty::Adt(id, args) => {
                let ItemKind::Struct(sd) = &self.krate.item(*id).kind else { return Ok(None) };
                let (ind, params) = self.ind_of(ty, span)?;
                let mut parts = Vec::new();
                for (j, fd) in sd.fields.iter().enumerate() {
                    let fh = fd.ty.subst(args);
                    let fty = self.ty(&fh, span)?;
                    let comp = self.proj(ind, params.clone(), t.clone(), j, sd.fields.len(), fty);
                    if let Some(p) = self.nat_range_opt(&fh, comp, span, depth + 1)? {
                        parts.push(p);
                    }
                }
                Ok(conj(parts))
            }
            Ty::Option(inner) => {
                let it = self.ty(inner, span)?;
                let saved = self.f.scope.clone();
                let r = (|| -> R<Option<Tm>> {
                    let lvl = self.push("v", Rel::Rel, &it, None)?;
                    let v = self.f.scope.var(lvl);
                    self.nat_range_opt(inner, v, span, depth + 1)
                })();
                self.f.scope = saved;
                let Some(body) = r? else { return Ok(None) };
                let unit = mk::ind(self.p.unit, vec![]);
                Ok(Some(Rc::new(Term::Match {
                    ind: self.p.option,
                    params: vec![it],
                    scrut: t,
                    motive: mk::ty(),
                    arms: vec![sandblaster_kernel::term::Arm { names: vec![], body: unit }, sandblaster_kernel::term::Arm { names: vec![Rc::from("v")], body }],
                })))
            }
            _ => Ok(None),
        }
    }

    /// `f::ensures` (`en`), or the Nat range `f::nat_range` (`None`).
    fn ensures_def_of(&mut self, id: ItemId, f: &'a FnDef, g: GlobalId, en: Option<&'a Ensures>) -> R<()> {
        let it = self.krate.item(id);
        let span = it.span;
        let name = format!("{}::{}", it.path, if en.is_some() { "ensures" } else { "nat_range" });
        let body_tm = self.env.global_body(g).ok_or_else(|| super::ElabError { span, msg: "no body".into(), kind: super::ErrKind::Internal })?;
        self.f = FnState::new(name.clone(), Some(id), &f.locals, span);
        self.f.mode = Mode::Proof;
        let (mut binders, _pending) = self.fn_params(f, span)?;
        self.fn_requires(f, &mut binders, Rel::Rel)?;
        // the stack-depth hypothesis of `decreases(.., max = C)` (so the
        // telescope matches `f`'s)
        if let Some(dec) = &f.decreases
            && let Some(max) = dec.max
        {
            let m = self.pure_expr(&dec.measure)?;
            let w = self.width_of(&dec.measure.ty, dec.measure.span)?;
            let p = self.holds(mk::prim(sandblaster_kernel::term::PrimOp::Le(w), vec![m, mk::lit(w, max)], vec![]));
            let lvl = self.push("h_depth", Rel::Rel, &p, None)?;
            self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lvl), origin: FactOrigin::Requires, span: dec.measure.span });
            self.f.scope.fact_tys.insert(lvl, p.clone());
            binders.push(super::items::TBinder { name: "h_depth".into(), rel: Rel::Rel, ty: p });
        }
        let arity = self.depth();
        // exec requires are irrelevant binders of `f`: apply them irrelevantly
        let rels = self.env.global_param_rels(g).unwrap_or_default();
        let mut app = mk::global(g);
        for (i, r) in rels.iter().enumerate() {
            app = Rc::new(Term::App { rel: *r, fun: app, arg: self.f.scope.var(i as u32) });
        }
        let ret_ty = self.ty(&f.ret, span)?;
        let goal = match en {
            Some(en) => self.ensures_prop(en, &ret_ty, app.clone(), span)?,
            None => self.nat_range_prop(&f.ret, app.clone(), span)?,
        };
        let ty = pi_tele(&binders, goal.clone());
        let full_goal = goal.clone();
        // walk the body (the committed body of `f`, `Rec` already replaced
        // by `f`): unfold `f x h` to it by conversion (transparent,
        // non-recursive) or `delta` (recursive, or opaque: functions with
        // loops, §5.6, whose `ensures` rests on the post-loop facts, §7.4)
        let inner = strip_lams(&body_tm, arity);
        let recursive = super::tm::any_node(&body_tm, &mut |n| matches!(n, Term::Global(h) if *h == g));
        let opaque = self.env.global_opaque(g) == Some(true);
        let mut recursion = Recursion::None;
        if recursive {
            // measure recursion with `f`'s measure: recursive calls of `f` in
            // the body get their ensures from recursive calls of `f::ensures`
            // (the induction hypotheses)
            let (m, w) = match &f.decreases {
                Some(dec) => (self.pure_expr(&dec.measure)?, self.width_of(&dec.measure.ty, dec.measure.span)?),
                None => match self.infer_measure_pub(id, f) {
                    Some(x) => x,
                    None => return super::unsupported(f.sig_span, "cannot infer a termination measure for the `ensures` proof; add `#[decreases(e)]`"),
                },
            };
            self.f.rec = Some(super::RecInfo { item: None, ty: ty.clone(), arity, measure: Some((m.clone(), w)) });
            self.ens_rec = Some((g, arity));
            recursion = Recursion::Measure { measure: m };
        }
        let mut goal = EnsGoal { en, ret: &f.ret, ret_ty: ret_ty.clone(), base: arity, span };
        let walked = self.walk_body(&inner, &mut goal);
        self.ens_rec = None;
        let mut proof = walked?;
        if recursive || opaque {
            // transport(R, body, f x h, sym(delta(f; x h)), z. Q[ret := z], proof)
            let args: Vec<Tm> = (0..arity).map(|i| self.f.scope.var(i)).collect();
            let delta = Rc::new(Term::Delta { def: g, args });
            let sym = mk::apps(mk::global(self.p.g("eq::sym")), [(Rel::Rel, ret_ty.clone()), (Rel::Rel, app.clone()), (Rel::Rel, inner.clone()), (Rel::Rel, delta)]);
            let saved = self.f.scope.clone();
            let motive = (|| -> R<Tm> {
                self.push("z", Rel::Rel, &ret_ty, None)?;
                match en {
                    Some(en) => self.ensures_prop(en, &shift(&ret_ty, 1), mk::var(0), span),
                    None => self.nat_range_prop(&f.ret, mk::var(0), span),
                }
            })();
            self.f.scope = saved;
            proof = Rc::new(Term::Transport { ty: ret_ty.clone(), lhs: inner.clone(), rhs: app.clone(), eq: sym, motive: motive?, val: proof });
        }
        let lam = lam_tele(&binders, proof);
        let failed = self.f.failed;
        let eg = self.add_definition(&name, DefKind::Ensures, Some(id), ty, lam, recursion, arity, false, failed, span)?;
        // a proof file attached summaries: the contract is the laws file's
        // part, `f::contract`, proven from `f::ensures`
        if en.is_some()
            && let Some(Some(cen)) = &f.spec.contract_ensures
            && !failed
        {
            let cg = self.contract_def(id, cen, eg, &binders, &full_goal, &app, &ret_ty, span)?;
            self.establish_by_contract(id, g, cg, arity);
        } else if en.is_some() && f.spec.contract_ensures.is_none() {
            self.establish_by_contract(id, g, eg, arity);
        }
        Ok(())
    }

    /// A lifted exec function whose contract (the laws file's `ensures`,
    /// DESIGN.md §15.6) is an equation `ret == E` — `E` not mentioning the
    /// function and spec-closed — is determined by it at once, at the
    /// identity view, as a `#[refines(E)]` would determine it: every
    /// implementation that satisfies it returns `E` on every valid input.
    /// It is therefore **established** for spec closure (§15.1: "fully
    /// specified in an earlier section with an identity view"): a
    /// specification may build its values (`Position::new(x)`, whose
    /// contract is `ret == Position(x, PhantomData)`, for a type whose
    /// fields the laws file cannot name). Only once the contract lemma
    /// `lemma` checked.
    fn establish_by_contract(&mut self, id: ItemId, g: GlobalId, lemma: GlobalId, arity: u32) {
        let lifted = self.krate.modules.get(self.krate.item(id).module.0 as usize).is_some_and(|m| m.lifted && !m.ghost);
        if !lifted || !self.defs.iter().any(|d| d.global == Some(lemma) && d.status == super::DefStatus::Checked) {
            return;
        }
        let Some(ty) = self.env.global_type(lemma) else { return };
        // `let ret = f x h; Eq(T, ret, E)` (`ensures_prop`), `E` free of `ret`
        let stmt = strip_pis(&ty, arity);
        let Term::Let { val, body, .. } = &*stmt else { return };
        let Term::Eq { lhs, rhs, .. } = &**body else { return };
        if !matches!(&**lhs, Term::Var(sandblaster_kernel::term::Idx(0))) || sandblaster_kernel::util::occurs(rhs, 0) {
            return;
        }
        let (head, args) = super::items::spine(val);
        if !matches!(&*head, Term::Global(h) if *h == g) || args.len() != arity as usize {
            return;
        }
        let e = shift(rhs, -1);
        if super::tm::any_node(&e, &mut |n| matches!(n, Term::Global(h) if *h == g)) || self.closure_violation(&[e], &[]).is_some() {
            return;
        }
        self.s1.established.insert(g);
    }

    /// `f::contract : Π(T..)(x..)(h : P..). L[x, f x h]` (DESIGN.md §15.6):
    /// the contract of a lifted function whose `ensures` a proof file
    /// extended with summaries — `L`, the laws file's `ensures` — proven
    /// from `f::ensures` (whose statement `full` is `L` conjoined with the
    /// summaries). `f::contract` is what `SPEC.lock` holds and what §15.5
    /// takes as `f`'s hypothesis; `f::ensures` stays the fact at call sites.
    #[allow(clippy::too_many_arguments)]
    fn contract_def(&mut self, id: ItemId, cen: &'a Ensures, eg: sandblaster_kernel::term::GlobalId, binders: &[super::items::TBinder], full: &Tm, app: &Tm, ret_ty: &Tm, span: Span) -> R<GlobalId> {
        let name = format!("{}::contract", self.krate.item(id).path);
        let goal = self.ensures_prop(cen, ret_ty, app.clone(), span)?;
        let ty = pi_tele(binders, goal.clone());
        let rels = self.env.global_param_rels(eg).unwrap_or_default();
        let mut pf = mk::global(eg);
        for (i, r) in rels.iter().enumerate() {
            pf = Rc::new(Term::App { rel: *r, fun: pf, arg: self.f.scope.var(i as u32) });
        }
        let (d0, saved) = (self.depth(), self.f.scope.clone());
        let proof = self.fact_in("h_ens", full.clone(), pf, FactOrigin::CalleeEnsures(eg), span, &mut |s| {
            let g = shift(&goal, (s.depth() - d0) as i64);
            s.prove_relevant(ObligationKind::Ensures, span, &g)
        });
        self.f.scope = saved;
        let proof = proof?;
        let failed = self.f.failed;
        let lam = lam_tele(binders, proof);
        self.add_definition(&name, DefKind::Ensures, Some(id), ty, lam, Recursion::None, binders.len() as u32, false, failed, span)
    }

    /// The induction hypotheses of a leaf of the `ensures` walk of a
    /// recursive `f`: for every full application `f a…` in `t`, the
    /// irrelevant fact `rec(a…; measure proof) : Q[a…, f a…]`.
    pub(super) fn with_induction_hyps(&mut self, t: &Tm, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let Some((g, arity)) = self.ens_rec else { return k(self) };
        let mut calls: Vec<Vec<Tm>> = Vec::new();
        let _ = super::tm::map_post(t, 0, &mut |n, b| {
            if b == 0 {
                let mut args = Vec::new();
                let mut head = &n;
                while let Term::App { fun, arg, .. } = &**head {
                    args.push(arg.clone());
                    head = fun;
                }
                if matches!(&**head, Term::Global(h) if *h == g) && args.len() == arity as usize {
                    args.reverse();
                    if !calls.iter().any(|c| c.len() == args.len() && c.iter().zip(&args).all(|(x, y)| Rc::ptr_eq(x, y))) {
                        calls.push(args);
                    }
                }
            }
            Some(n)
        });
        // the recursive calls the path conditions mention (`let (x, r) =
        // f(rest)?` matches on a call whose result the value only
        // projects): an induction hypothesis each, when the measure is
        // seen to decrease (tried silently)
        let d = self.depth();
        let sc = &self.f.scope;
        let mut more: Vec<Vec<Tm>> = Vec::new();
        let mut lvls: Vec<u32> = sc.fact_tys.keys().copied().filter(|l| *l < d && !sc.hidden.contains(l)).collect();
        lvls.sort();
        for l in lvls {
            let Some(ft) = sc.fact_tys.get(&l) else { continue };
            let ft = shift(ft, (d - l) as i64);
            let Term::Eq { lhs, rhs, .. } = &*ft else { continue };
            for side in [lhs, rhs] {
                let (h, args) = super::items::spine(side);
                if matches!(&*h, Term::Global(x) if *x == g) && args.len() == arity as usize && !calls.iter().chain(more.iter()).any(|c| c.iter().zip(&args).all(|(x, y)| self.env.alpha_eq_relevant(x, y, &|a, b| a == b))) {
                    more.push(args);
                }
            }
        }
        // the recursive calls bound by a `let` of the body (`let p = f(n -
        // 1, ..); S { h: p.h + 1, .. }`: the value only mentions `p`)
        let mut let_lvls: Vec<u32> = sc.let_tms.keys().copied().filter(|l| *l < d).collect();
        let_lvls.sort();
        for l in let_lvls {
            let (Some(e), Some((_, val, v0))) = (sc.ctx.entries.get(l as usize), sc.let_tms.get(&l)) else { continue };
            // the recorded value belongs to this binder
            if !matches!(&e.def, Some(sandblaster_kernel::value::Arg::Rel(v)) if Rc::ptr_eq(v, v0)) {
                continue;
            }
            let val = shift(val, (d - l) as i64);
            let (h, args) = super::items::spine(&val);
            if matches!(&*h, Term::Global(x) if *x == g) && args.len() == arity as usize && !calls.iter().chain(more.iter()).any(|c| c.iter().zip(&args).all(|(x, y)| self.env.alpha_eq_relevant(x, y, &|a, b| a == b))) {
                more.push(args);
            } else if super::lockstep::IH_IN_CHOICES.with(|c| c.get()) {
                // a lockstep (layered proofs) also takes the recursive calls
                // inside a `let`-bound choice (`let child = if left { f(..) }
                // else { f(..) }`), each tried like the others (its measure
                // must be seen to decrease here)
                let _ = super::tm::map_post(&val, 0, &mut |n, b| {
                    if b == 0 {
                        let (h, args) = super::items::spine(&n);
                        if matches!(&*h, Term::Global(x) if *x == g) && args.len() == arity as usize && !calls.iter().chain(more.iter()).any(|c| c.iter().zip(&args).all(|(x, y)| self.env.alpha_eq_relevant(x, y, &|a, b| a == b))) {
                            more.push(args);
                        }
                    }
                    Some(n)
                });
            }
        }
        for args in more {
            let Some(r) = self.f.rec.clone() else { break };
            let Some((m, w)) = r.measure.clone() else { break };
            let (no, nd, failed) = (self.obligations.len(), self.diags.list.len(), self.f.failed);
            let ns = self.f.slot_failures.as_ref().map(|v| v.len());
            let ok = self.measure_proof(&m, w, r.arity, &args, self.f.span).is_ok() && self.obligations[no..].iter().all(|o| o.proven());
            self.obligations.truncate(no);
            self.diags.list.truncate(nd);
            self.f.failed = failed;
            if let (Some(v), Some(n)) = (self.f.slot_failures.as_mut(), ns) {
                v.truncate(n);
            }
            if ok {
                calls.push(args);
            }
        }
        self.ih_chain(calls, 0, k)
    }

    fn ih_chain(&mut self, calls: Vec<Vec<Tm>>, i: usize, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let Some(args) = calls.get(i).cloned() else { return k(self) };
        let r = self.f.rec.clone().ok_or_else(|| super::ElabError { span: self.f.span, msg: "ensures recursion".into(), kind: super::ErrKind::Internal })?;
        let span = self.f.span;
        let (m, w) = r.measure.clone().unwrap();
        let proof = self.measure_proof(&m, w, r.arity, &args, span)?;
        let ih = Rc::new(Term::Rec { args: args.clone(), proof: Some(proof) });
        let ty = super::tm::subst_closed(&strip_pis(&r.ty, r.arity), &args);
        // the statement's own proofs (e.g. a refinement's spec-side
        // obligations) are instantiated: re-certify their linear arithmetic
        let ty = super::recert::recertify(&self.env, &self.f.scope.ctx, &ty);
        let saved = self.f.scope.clone();
        let lvl = self.push("ih", Rel::Irr, &ty, Some(&ih))?;
        self.f.scope.facts.push(crate::prover::FactRef { lvl: sandblaster_kernel::term::Lvl(lvl), origin: FactOrigin::InductionHyp, span });
        self.f.scope.fact_tys.insert(lvl, ty.clone());
        let body = self.ih_chain(calls.into_iter().map(|c| c.iter().map(|a| shift(a, 1)).collect()).collect(), i + 1, k);
        self.f.scope = saved;
        Ok(mk::let_("ih", Rel::Irr, ty, ih, body?))
    }

    /// A relevant proof of `goal` (a term at the current depth): the
    /// prover's relevant proof, or — when that fails and the goal's proofs
    /// carry no information ([`Elab::promote_irr`]) — an irrelevant proof,
    /// for which every fact of the context is usable (e.g. a conjunction of
    /// equations given by an irrelevant post-loop fact, DESIGN.md §7.4),
    /// promoted. The irrelevant attempt replaces the failed one in the
    /// records only if it succeeds.
    pub(super) fn prove_relevant(&mut self, kind: ObligationKind, span: Span, goal: &Tm) -> R<Tm> {
        let (nobl, ndiag, failed) = (self.obligations.len(), self.diags.list.len(), self.f.failed);
        let p = self.prove(kind.clone(), span, goal, true)?;
        let erased: Tm = Rc::new(Term::Erased);
        if self.obligations[nobl..].iter().all(|o| o.proven()) || self.promote_irr(goal, &erased, 16).is_none() {
            return Ok(p);
        }
        let (obls, diags) = (self.obligations.split_off(nobl), self.diags.list.split_off(ndiag));
        self.f.failed = failed;
        let q = self.prove(kind, span, goal, false)?;
        if self.obligations[nobl..].iter().all(|o| o.proven())
            && let Some(r) = self.promote_irr(goal, &q, 16)
        {
            return Ok(r);
        }
        self.obligations.truncate(nobl);
        self.diags.list.truncate(ndiag);
        self.obligations.extend(obls);
        self.diags.list.extend(diags);
        self.f.failed = true;
        Ok(p)
    }

    /// A relevant proof of the proposition `ty` (a term at the current
    /// depth) from the irrelevant proof `p`, when `ty` is — after `let`s and
    /// the unfolding of transparent definitions (`Not`, `And`, `Iff`, spec
    /// predicates) — built from equations, `Π`, `Σ`, `Unit` and `Empty`:
    /// `eq::promote` at the equations (its proof argument is irrelevant),
    /// `λ`, pairs and `absurd` around them. `None` for anything else (`Or`,
    /// `Exists`, stuck predicates), whose proofs carry information.
    pub(super) fn promote_irr(&self, ty: &Tm, p: &Tm, fuel: u32) -> Option<Tm> {
        if fuel == 0 {
            return None;
        }
        match &**ty {
            Term::Eq { ty: a, lhs, rhs } => Some(mk::apps(mk::global(self.p.g("eq::promote")), [(Rel::Rel, a.clone()), (Rel::Rel, lhs.clone()), (Rel::Rel, rhs.clone()), (Rel::Irr, p.clone())])),
            Term::Let { name, rel, ty: lt, val, body } => {
                let inner = self.promote_irr(body, &shift(p, 1), fuel)?;
                Some(mk::let_(name, *rel, lt.clone(), val.clone(), inner))
            }
            Term::Pi { name, rel, dom, cod } => {
                let x = Rc::new(Term::App { rel: *rel, fun: shift(p, 1), arg: mk::var(0) });
                let inner = self.promote_irr(cod, &x, fuel - 1)?;
                Some(mk::lam(name, *rel, dom.clone(), inner))
            }
            Term::Sigma { snd_rel, fst, snd, .. } => {
                let a = self.promote_irr(fst, &mk::fst(p.clone()), fuel - 1)?;
                let b = match snd_rel {
                    Rel::Rel => self.promote_irr(&super::tm::subst0(snd, &a), &mk::snd(p.clone()), fuel - 1)?,
                    Rel::Irr => mk::snd(p.clone()),
                };
                Some(mk::pair(ty.clone(), a, b))
            }
            Term::Ind { ind, .. } if *ind == self.p.unit => Some(self.unit_val()),
            Term::Ind { ind, .. } if *ind == self.env.empty_ind() => Some(Rc::new(Term::Absurd { ty: ty.clone(), proof: p.clone() })),
            Term::Ind { .. } => None,
            // a proposition by cases: a match whose arms are propositions
            // (a `match`/`if` in a statement, `o.is_some() && ..`), alone or
            // in the dependent idiom `(match s .. λ(e : Eq(D, s, y)). ..) refl`
            Term::Match { .. } => self.promote_match(ty, None, p, fuel),
            Term::App { rel, fun, arg } if matches!(&**fun, Term::Match { .. }) => self.promote_match(fun, Some((*rel, arg.clone())), p, fuel),
            _ => {
                let t2 = super::tm::head_unfold(&self.env, ty, &|t| matches!(t, Term::Eq { .. } | Term::Pi { .. } | Term::Sigma { .. } | Term::Ind { .. } | Term::Match { .. }))?;
                self.promote_irr(&t2, p, fuel - 1)
            }
        }
    }

    /// [`Elab::promote_irr`] of a proposition by cases: `m` is a match whose
    /// motive returns a type (`y. Type`), or — with `app = Some((rel, a))`,
    /// the dependent idiom `m a` — a function type `y. Π(e : E). Type` whose
    /// arms are `λ(e : E). Tₖ`. The proof matches on the same scrutinee and
    /// promotes in each arm, where the proposition computes to its arm:
    ///
    /// `(match s as y return Π(e : E). Π(.h : M(y) e). M(y) e with
    ///   Cₖ(x̄) ⇒ λe. λ.h. promote(Tₖ, h)) a .p`
    ///
    /// (`M(y)` is `m` with the scrutinee `y`; without `app` the same with no
    /// `e`). `None` when an arm is not a proposition `promote_irr` handles.
    fn promote_match(&self, m: &Tm, app: Option<(Rel, Tm)>, p: &Tm, fuel: u32) -> Option<Tm> {
        if fuel == 0 {
            return None;
        }
        let Term::Match { ind, params, scrut, motive, arms } = &**m else { return None };
        // the motive's body: `Type`, or `Π(e : E). Type` for the idiom
        let sort = |t: &Term| matches!(t, Term::Sort(_));
        let e_binder = match (&**motive, &app) {
            (b, None) if sort(b) => None,
            (Term::Pi { name, rel, dom, cod }, Some((arel, _))) if sort(cod) && rel == arel => Some((name.clone(), *rel, dom.clone())),
            _ => return None,
        };
        let k: i64 = if e_binder.is_some() { 2 } else { 1 };
        // `M(y)` (applied to `e`), under the binders `y` [`e`]
        let m_y = {
            let arms_k: Vec<sandblaster_kernel::term::Arm> = arms.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: shift_from(&a.body, k, a.names.len() as u32) }).collect();
            let mt: Tm = Rc::new(Term::Match { ind: *ind, params: params.iter().map(|t| shift(t, k)).collect(), scrut: mk::var((k - 1) as u32), motive: shift_from(motive, k, 1), arms: arms_k });
            match &e_binder {
                Some((_, rel, _)) => Rc::new(Term::App { rel: *rel, fun: mt, arg: mk::var(0) }),
                None => mt,
            }
        };
        let inner = mk::pi("h", Rel::Irr, m_y.clone(), shift(&m_y, 1));
        let new_motive = match &e_binder {
            Some((name, rel, dom)) => mk::pi(name, *rel, dom.clone(), inner),
            None => inner,
        };
        let mut new_arms = Vec::with_capacity(arms.len());
        for a in arms {
            let body = match &e_binder {
                Some(_) => {
                    let Term::Lam { name, rel, dom, body: tk } = &*a.body else { return None };
                    let pr = self.promote_irr(&shift(tk, 1), &mk::var(0), fuel - 1)?;
                    mk::lam(name, *rel, dom.clone(), mk::lam("h", Rel::Irr, tk.clone(), pr))
                }
                None => {
                    let pr = self.promote_irr(&shift(&a.body, 1), &mk::var(0), fuel - 1)?;
                    mk::lam("h", Rel::Irr, a.body.clone(), pr)
                }
            };
            new_arms.push(sandblaster_kernel::term::Arm { names: a.names.clone(), body });
        }
        let mt: Tm = Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: scrut.clone(), motive: new_motive, arms: new_arms });
        let applied = match app {
            Some((rel, a)) => Rc::new(Term::App { rel, fun: mt, arg: a }),
            None => mt,
        };
        Some(mk::app_irr(applied, p.clone()))
    }

    /// `Q[ret := v]` as `let ret : R = v; Q`.
    fn ensures_prop(&mut self, en: &'a Ensures, ret_ty: &Tm, v: Tm, span: Span) -> R<Tm> {
        let saved = self.f.scope.clone();
        let r = (|| -> R<Tm> {
            let lvl = self.push("ret", Rel::Rel, ret_ty, Some(&v))?;
            if let PatKind::Binding { local, .. } = &en.binder.kind {
                self.f.scope.locals.insert(*local, lvl);
            }
            let q = self.prop(&en.prop)?;
            Ok(mk::let_("ret", Rel::Rel, ret_ty.clone(), v.clone(), q))
        })();
        self.f.scope = saved;
        let _ = span;
        r
    }

    /// Mirrors the body structure (lets, dependent matches, plain matches);
    /// proves the goal of `g` at each leaf, in that leaf's context.
    ///
    /// A dependent match `(match s as y return Π(e : Eq(D, s, y)). R with
    /// arms) a` of the body is mirrored by `(match s as y return Π(e :
    /// Eq(D, s, y)). G[(match y … arms) e] with arms') refl(D, s)` (`G` the
    /// goal of `g`): in the arm of constructor `K`, `G[(match K … arms) e]`
    /// computes to `G[arm_K]`, which the walk proves recursively (the arm's
    /// own path equation is the mirror's `e`). A plain match is mirrored the
    /// same way without the equation.
    pub(super) fn walk_body(&mut self, t: &Tm, g: &mut dyn WalkGoal<'a>) -> R<Tm> {
        match &**t {
            // a join `let j = M; j`: the value is `M`
            Term::Let { rel: Rel::Rel, val, body, .. } if matches!(&**body, Term::Var(sandblaster_kernel::term::Idx(0))) => self.walk_body(val, g),
            Term::Let { name, rel, ty, val, body } => {
                let saved = self.f.scope.clone();
                // an irrelevant `let` (a fact) is abstract in the walk: its
                // proof carries nothing a goal can depend on, and unfolding
                // it (e.g. the projections of a post-loop fact's proof into
                // the types of the later conjuncts) only makes the provers'
                // read-back of the context blow up; a proof built without
                // the definition is valid with it
                let lvl = self.push(name, *rel, ty, (*rel == Rel::Rel).then_some(val))?;
                if *rel == Rel::Irr && self.is_refines_fact(val) {
                    self.f.scope.ref_facts.push((lvl, ty.clone()));
                }
                let p = self.walk_body(body, g);
                self.f.scope = saved;
                Ok(mk::let_(name, *rel, ty.clone(), val.clone(), p?))
            }
            Term::App { rel: Rel::Irr, fun, .. } if matches!(&**fun, Term::Match { motive, scrut, .. } if matches!(&**motive, Term::Pi { .. }) && g.splits(scrut)) => {
                let Term::Match { ind, params, scrut, motive, arms } = &**fun else { unreachable!() };
                if let Some(p) = self.walk_known_ctor(*ind, params, scrut, arms, true, g)? {
                    return Ok(p);
                }
                self.walk_match(*ind, params, scrut, motive, arms, true, g)
            }
            Term::Match { ind, params, scrut, motive, arms } if !matches!(&**motive, Term::Pi { .. }) && g.splits(scrut) => {
                if let Some(p) = self.walk_known_ctor(*ind, params, scrut, arms, false, g)? {
                    return Ok(p);
                }
                let single = self.env.inductive_decl(*ind).is_some_and(|d| d.ctors.len() == 1);
                // a getter's tail `match s { C(f̄) => f_i }`: the arm is a field binder
                let getter = arms.len() == 1 && matches!(&*arms[0].body, Term::Var(i) if (i.0 as usize) < arms[0].names.len());
                let var_proj = g.eq_on_var_projections() && getter && matches!(&**scrut, Term::Var(_));
                let proj = ((g.eq_on_projections() || var_proj) && single) || g.eq_on_all();
                if proj { self.walk_match_eq(*ind, params, scrut, motive, arms, g) } else { self.walk_match(*ind, params, scrut, motive, arms, false, g) }
            }
            // an unreachable tail (`unreachable!()`, the `else` of a `let ..
            // else`): the body's own proof that it is not reached (a term of
            // this context: the walk mirrors the body's binders) proves any
            // goal there — the prover would have to rebuild it from path
            // equations it may only have in erased form
            Term::Absurd { proof, .. } => {
                let ty = g.goal(self, t)?;
                Ok(Rc::new(Term::Absurd { ty, proof: proof.clone() }))
            }
            _ => g.leaf(self, t),
        }
    }

    /// The body of an arm of a split match, its fields and path equation in
    /// scope: closed by `absurd` when the goal says it is impossible
    /// ([`WalkGoal::prune`]), else walked.
    fn walk_arm(&mut self, body: &Tm, g: &mut dyn WalkGoal<'a>) -> R<Tm> {
        if let Some(p) = g.prune(self)? {
            let ty = g.goal(self, body)?;
            return Ok(Rc::new(Term::Absurd { ty, proof: p }));
        }
        g.arm(self, true);
        let r = self.walk_body(body, g);
        g.arm(self, false);
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_match(&mut self, ind: sandblaster_kernel::term::IndId, params: &[Tm], scrut: &Tm, motive: &Tm, arms: &[sandblaster_kernel::term::Arm], idiom: bool, g: &mut dyn WalkGoal<'a>) -> R<Tm> {
        let span = self.f.span;
        let decl = self.env.inductive_decl(ind).ok_or_else(|| super::ElabError { span, msg: "unknown inductive".into(), kind: super::ErrKind::Internal })?;
        let d_ty = mk::ind(ind, params.to_vec());
        let k: i64 = if idiom { 2 } else { 1 };
        // the motive: `G[(match y … arms) e]` at depth d + k
        let saved = self.f.scope.clone();
        let motive_body = (|| -> R<Tm> {
            self.push("y", Rel::Rel, &d_ty, None)?;
            if idiom {
                let ety = mk::eq(shift(&d_ty, 1), shift(scrut, 1), mk::var(0));
                self.push("e", Rel::Irr, &ety, None)?;
            }
            let orig = Rc::new(Term::Match { ind, params: params.to_vec(), scrut: scrut.clone(), motive: motive.clone(), arms: arms.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: a.body.clone() }).collect() });
            let Term::Match { params: sp, motive: sm, arms: sa, .. } = &*shift(&orig, k) else { unreachable!() };
            let inner = Rc::new(Term::Match { ind, params: sp.clone(), scrut: mk::var((k - 1) as u32), motive: sm.clone(), arms: sa.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: a.body.clone() }).collect() });
            let inner = if idiom { Rc::new(Term::App { rel: Rel::Irr, fun: inner, arg: mk::var(0) }) } else { inner };
            g.goal(self, &inner)
        })();
        self.f.scope = saved;
        let motive_body = motive_body?;
        let our_motive = if idiom { mk::pi("e", Rel::Irr, mk::eq(shift(&d_ty, 1), shift(scrut, 1), mk::var(0)), motive_body) } else { motive_body };
        // the arms
        let mut our_arms = Vec::new();
        for (ci, (c, arm)) in decl.ctors.iter().zip(arms).enumerate() {
            let saved = self.f.scope.clone();
            let nf = c.fields.len() as u32;
            let r = (|| -> R<Tm> {
                // field types: the constructor's, instantiated with the parameters
                let mut field_tys = Vec::new();
                for (j, (_, _, fty)) in c.fields.iter().enumerate() {
                    // `fty` lives in [params, fields < j]; here: [d, fields < j]
                    let mut args: Vec<Tm> = params.iter().map(|p| shift(p, j as i64)).collect();
                    args.extend((0..j as u32).rev().map(mk::var));
                    field_tys.push(super::tm::subst_closed(fty, &args));
                }
                for ((name, rel, _), fty) in c.fields.iter().zip(&field_tys) {
                    self.push(name, *rel, fty, None)?;
                }
                let body = &arm.body;
                if idiom {
                    let ctor_t = mk::ctor(ind, ci as u32, params.iter().map(|p| shift(p, nf as i64)).collect(), (0..nf).rev().map(mk::var).collect());
                    let ety = mk::eq(shift(&d_ty, nf as i64), shift(scrut, nf as i64), ctor_t.clone());
                    let le = self.push("e", Rel::Irr, &ety, None)?;
                    // its statement term (the recursive calls it mentions get
                    // induction hypotheses, `with_induction_hyps`)
                    self.f.scope.fact_tys.insert(le, ety.clone());
                    // the arm body is `λ(e). B`: walk `B` (its `e` is ours)
                    let b = match &**body {
                        Term::Lam { body, .. } => body.clone(),
                        _ => return super::internal(span, "dependent-match arm without its equation"),
                    };
                    // the callee refinements about the scrutinee, at this
                    // constructor (DESIGN.md §15.2: refinements compose)
                    let derived = self.refines_at_path(&shift(&d_ty, nf as i64), &shift(scrut, nf as i64), &ctor_t, le);
                    let n = derived.len() as i64;
                    for (ty, pf) in &derived {
                        self.push_fact_rel("h_ref_at", Rel::Irr, ty, Some(pf), FactOrigin::PathCond, span)?;
                    }
                    let mut p = self.walk_arm(&shift(&b, n), g)?;
                    for (ty, pf) in derived.into_iter().rev() {
                        p = mk::let_("h_ref_at", Rel::Irr, ty, pf, p);
                    }
                    Ok(mk::lam("e", Rel::Irr, ety, p))
                } else {
                    self.walk_arm(body, g)
                }
            })();
            self.f.scope = saved;
            our_arms.push(sandblaster_kernel::term::Arm { names: arm.names.clone(), body: r? });
        }
        let m = Rc::new(Term::Match { ind, params: params.to_vec(), scrut: scrut.clone(), motive: our_motive, arms: our_arms });
        Ok(if idiom { Rc::new(Term::App { rel: Rel::Irr, fun: m, arg: mk::refl(d_ty, scrut.clone()) }) } else { m })
    }
}

impl<'a> Elab<'a> {
    /// A plain match whose scrutinee evaluates to a constructor (a tuple
    /// built by a transparent function: `let (a, b) = s.split_at(n)`): the
    /// arm is selected and its fields are `let`-bound to the constructor's
    /// arguments, so the leaf goals see their values (`a` is the prefix of
    /// `s`) instead of opaque field binders. The mirror `let x̄ = v̄; p`
    /// proves the goal at the match by conversion (ι after δ).
    #[allow(clippy::too_many_arguments)]
    fn walk_known_ctor(&mut self, ind: sandblaster_kernel::term::IndId, params: &[Tm], scrut: &Tm, arms: &[sandblaster_kernel::term::Arm], idiom: bool, g: &mut dyn WalkGoal<'a>) -> R<Option<Tm>> {
        if self.env.inductive_decl(ind).is_none_or(|d| d.ctors.len() != 1) {
            return Ok(None);
        }
        let Ok(v) = self.eval(scrut) else { return Ok(None) };
        let sandblaster_kernel::value::Value::Ctor { ctor: 0, args, .. } = &*v else { return Ok(None) };
        let (Some(arm), Some(decl)) = (arms.first(), self.env.inductive_decl(ind)) else { return Ok(None) };
        let c = &decl.ctors[0];
        if args.len() != c.fields.len() || arm.names.len() != args.len() || c.fields.iter().any(|f| f.1 != Rel::Rel) {
            return Ok(None);
        }
        // the field values and types, quoted at the current depth
        let mut vals: Vec<(String, Tm, Tm)> = Vec::new();
        for (a, (fname, _, _)) in args.iter().zip(&c.fields) {
            let sandblaster_kernel::value::Arg::Rel(av) = a else { return Ok(None) };
            let val = self.quote(av, None);
            let Ok(ty) = self.env.infer(&self.f.scope.ctx, &val, &mut sandblaster_kernel::value::Budget { steps: self.opts.goal_budget }) else { return Ok(None) };
            let ty = self.quote(&ty, None);
            vals.push((fname.to_string(), val, ty));
        }
        let n = vals.len() as u32;
        let d_ty = mk::ind(ind, params.to_vec());
        // the idiom's path equation `e : Eq(D, s, C(x̄))`, by `refl` (s ≡ C(v̄))
        let e_let = idiom.then(|| {
            let ctor_t = mk::ctor(ind, 0, params.iter().map(|p| shift(p, n as i64)).collect(), (0..n).rev().map(mk::var).collect());
            let ety = mk::eq(shift(&d_ty, n as i64), shift(scrut, n as i64), ctor_t);
            (ety, mk::refl(shift(&d_ty, n as i64), shift(scrut, n as i64)))
        });
        let body = match (&e_let, &*arm.body) {
            (Some(_), Term::Lam { body, .. }) => body.clone(),
            (Some(_), _) => return Ok(None),
            (None, _) => arm.body.clone(),
        };
        let saved = self.f.scope.clone();
        let r = (|| -> R<Tm> {
            for (j, (name, val, ty)) in vals.iter().enumerate() {
                self.push(name, Rel::Rel, &shift(ty, j as i64), Some(&shift(val, j as i64)))?;
            }
            if let Some((ety, pf)) = &e_let {
                self.push_fact_rel("e", Rel::Irr, ety, Some(pf), FactOrigin::PathCond, self.f.span)?;
            }
            self.walk_body(&body, g)
        })();
        self.f.scope = saved;
        let mut p = r?;
        if let Some((ety, pf)) = e_let {
            p = mk::let_("e", Rel::Irr, ety, pf, p);
        }
        for (j, (name, val, ty)) in vals.into_iter().enumerate().rev() {
            p = mk::let_(&name, Rel::Rel, shift(&ty, j as i64), shift(&val, j as i64), p);
        }
        Ok(Some(p))
    }

    /// Whether an irrelevant `let` value of a body is a call-site
    /// refinement fact: an application of a `::refines` lemma.
    fn is_refines_fact(&self, val: &Tm) -> bool {
        let mut h = val;
        while let Term::App { fun, .. } = &**h {
            h = fun;
        }
        matches!(&**h, Term::Global(g) if self.env.global_kind(*g) == Some(DefKind::Ensures) && self.env.global_name(*g).is_some_and(|n| n.ends_with("::refines")))
    }

    /// In the arm of a dependent match on `scrut` whose path equation `e :
    /// Eq(D, scrut, C(v̄))` is at level `le` (the arm's `nf` fields just
    /// before it): for every call-site refinement fact `h : Eq(V, L[scrut],
    /// R)` in scope whose left side mentions `scrut` (the view of the
    /// callee's result), the fact `Eq(V, L[C(v̄)], R)` proven by
    /// `transport(D, scrut, C(v̄), e, z. Eq(V, L[z], R), h)` (types and
    /// proofs at the current depth). Its left side computes to a
    /// constructor (`None`, `Some(α v)`, a tuple), so the prover can
    /// rewrite the spec call `R` — unfolded by evaluation like the spec
    /// call inside the goal — to it; the plain `h` relates two unfolded
    /// bodies and is rarely usable.
    fn refines_at_path(&mut self, d_ty: &Tm, scrut: &Tm, ctor_t: &Tm, le: u32) -> Vec<(Tm, Tm)> {
        // the arguments are terms at depth `le` (before `e`); here: `le + 1`
        let d = self.depth();
        if d != le + 1 || self.f.scope.ref_facts.is_empty() {
            return vec![];
        }
        let (dty, s_here, c_here) = (shift(d_ty, 1), shift(scrut, 1), shift(ctor_t, 1));
        let mut out = Vec::new();
        for (lvl, ty0) in self.f.scope.ref_facts.clone() {
            if lvl >= le {
                continue;
            }
            let fty = shift(&ty0, (d - lvl) as i64);
            let Term::Eq { ty: vty, lhs, rhs } = &*fty else { continue };
            // `L[z]` at depth d + 1 (z = Var(0)); `R` must not mention `scrut`
            let Some(l_abs) = super::tm::abstract_syntactic(&self.env, lhs, &s_here) else { continue };
            if super::tm::abstract_syntactic(&self.env, rhs, &s_here).is_some() {
                continue;
            }
            let l_at = super::tm::simp_redexes(&super::tm::subst0(&l_abs, &c_here));
            let new_ty = mk::eq(vty.clone(), l_at, rhs.clone());
            let motive = mk::eq(shift(vty, 1), l_abs.clone(), shift(rhs, 1));
            let e_var = mk::var(d - 1 - le);
            let h_var = mk::var(d - 1 - lvl);
            let pf = Rc::new(Term::Transport { ty: dty.clone(), lhs: s_here.clone(), rhs: c_here.clone(), eq: e_var, motive, val: h_var });
            // the transport must type-check: the fact is dropped otherwise
            let wrapped = mk::let_("h", Rel::Irr, new_ty.clone(), pf.clone(), self.unit_val());
            let Ok(unit) = self.eval(&mk::ind(self.p.unit, vec![])) else { continue };
            let mut b = sandblaster_kernel::value::Budget { steps: self.opts.goal_budget };
            if self.env.check(&self.f.scope.ctx, &wrapped, &unit, &mut b).is_ok() {
                out.push((new_ty, pf));
            }
        }
        out
    }

    /// A plain match on a single-constructor value mirrored with its path
    /// equation (see [`WalkGoal::eq_on_projections`]): `(match s as y
    /// return Π(e :Irr Eq(D, s, y)). G[(match y … arms)] with | C(f̄) =>
    /// λe. <walk of the arm>) refl(D, s)`.
    fn walk_match_eq(&mut self, ind: sandblaster_kernel::term::IndId, params: &[Tm], scrut: &Tm, motive: &Tm, arms: &[sandblaster_kernel::term::Arm], g: &mut dyn WalkGoal<'a>) -> R<Tm> {
        let span = self.f.span;
        let decl = self.env.inductive_decl(ind).ok_or_else(|| super::ElabError { span, msg: "unknown inductive".into(), kind: super::ErrKind::Internal })?;
        let d_ty = mk::ind(ind, params.to_vec());
        let saved = self.f.scope.clone();
        let motive_body = (|| -> R<Tm> {
            self.push("y", Rel::Rel, &d_ty, None)?;
            let ety = mk::eq(shift(&d_ty, 1), shift(scrut, 1), mk::var(0));
            self.push("e", Rel::Irr, &ety, None)?;
            let orig = Rc::new(Term::Match { ind, params: params.to_vec(), scrut: scrut.clone(), motive: motive.clone(), arms: arms.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: a.body.clone() }).collect() });
            let Term::Match { params: sp, motive: sm, arms: sa, .. } = &*shift(&orig, 2) else { unreachable!() };
            let inner = Rc::new(Term::Match { ind, params: sp.clone(), scrut: mk::var(1), motive: sm.clone(), arms: sa.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: a.body.clone() }).collect() });
            g.goal(self, &inner)
        })();
        self.f.scope = saved;
        let our_motive = mk::pi("e", Rel::Irr, mk::eq(shift(&d_ty, 1), shift(scrut, 1), mk::var(0)), motive_body?);
        let mut our_arms = Vec::new();
        for (ci, (c, arm)) in decl.ctors.iter().zip(arms).enumerate() {
            let saved = self.f.scope.clone();
            let nf = c.fields.len() as u32;
            let r = (|| -> R<Tm> {
                for (j, (name, rel, fty)) in c.fields.iter().enumerate() {
                    let mut args: Vec<Tm> = params.iter().map(|p| shift(p, j as i64)).collect();
                    args.extend((0..j as u32).rev().map(mk::var));
                    let t = super::tm::subst_closed(fty, &args);
                    self.push(name, *rel, &t, None)?;
                }
                let ctor_t = mk::ctor(ind, ci as u32, params.iter().map(|p| shift(p, nf as i64)).collect(), (0..nf).rev().map(mk::var).collect());
                let ety = mk::eq(shift(&d_ty, nf as i64), shift(scrut, nf as i64), ctor_t);
                self.push_fact_rel("e", Rel::Irr, &ety, None, FactOrigin::PathCond, span)?;
                let p = self.walk_arm(&shift(&arm.body, 1), g)?;
                Ok(mk::lam("e", Rel::Irr, ety, p))
            })();
            self.f.scope = saved;
            our_arms.push(sandblaster_kernel::term::Arm { names: arm.names.clone(), body: r? });
        }
        let m = Rc::new(Term::Match { ind, params: params.to_vec(), scrut: scrut.clone(), motive: our_motive, arms: our_arms });
        Ok(Rc::new(Term::App { rel: Rel::Irr, fun: m, arg: mk::refl(d_ty, scrut.clone()) }))
    }
}

pub(super) fn strip_pis(t: &Tm, n: u32) -> Tm {
    let mut t = t.clone();
    for _ in 0..n {
        let next = match &*t {
            Term::Pi { cod, .. } => cod.clone(),
            _ => return t,
        };
        t = next;
    }
    t
}

pub(super) fn strip_lams(t: &Tm, n: u32) -> Tm {
    let mut t = t.clone();
    for _ in 0..n {
        let next = match &*t {
            Term::Lam { body, .. } => body.clone(),
            _ => return t,
        };
        t = next;
    }
    t
}

