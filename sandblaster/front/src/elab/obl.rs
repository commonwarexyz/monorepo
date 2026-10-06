//! Proof obligations (DESIGN.md §7.2): every proof slot the elaborator
//! creates is filled here, by evaluation (`refl` of a closed goal) or by the
//! prover chain, and recorded for the report and diagnostics.
//!
//! The target is a proposition term in the current context; the goal given
//! to the prover carries exactly that context (facts are its binders). A
//! failed obligation marks the current definition as unproven, emits an
//! `error[obligation]` diagnostic with the goal, the facts and what the
//! prover tried, and returns a placeholder (the definition is then not
//! submitted to the kernel).

use std::rc::Rc;

use sandblaster_kernel::term::{Lvl, Rel, Term, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Budget, Value};

use super::{Elab, OblStatus, ObligationRecord, R};

thread_local! {
    /// Inside the forward-chained slot of a completeness script (no second
    /// chaining).
    static CHAINING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Inside a slot whose Nat range facts are bound (no second binding).
    static NAT_RANGES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Inside the first, range-free attempt at a goal whose Nat range facts
    /// exist: the prover's step budget is a 32nd of a goal's.
    static RANGE_FREE_TRY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Inside an attempted lemma application (`Elab::try_lemma_app`, the
    /// induction hypotheses of `by_induction(..)`): the prover's step budget
    /// is an eighth of a goal's.
    pub(super) static TRY_BUDGET: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}
use crate::diag::{DiagKind, Diagnostic};
use crate::prover::{AutoFailure, Goal, Hint, ObligationId, ObligationKind, Prover};
use crate::span::Span;

/// Maximum length of recorded goal texts.
const GOAL_TEXT_MAX: usize = 600;

fn trunc(mut s: String) -> String {
    if s.len() > GOAL_TEXT_MAX {
        let mut cut = GOAL_TEXT_MAX;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push('…');
    }
    s
}

/// The explanation attached to a failed `invariant-exit` obligation.
pub const INVARIANT_EXIT_NOTE: &str = "loop invariants must also hold when the loop exits: after the last iteration of `for i in a..b` at `i = b` (`i_exit`), of `a..=b` at `i = b + 1`, and for `while` where the condition is false; a bound such as `i < b` is already a fact inside the loop body, so drop it or weaken it to `i <= b` (DESIGN.md §7.4)";

/// Human name of an obligation kind (diagnostics and the report).
pub fn kind_name(k: &ObligationKind) -> &'static str {
    match k {
        ObligationKind::Overflow => "overflow",
        ObligationKind::Underflow => "underflow",
        ObligationKind::DivZero => "div-zero",
        ObligationKind::ShiftWidth => "shift-width",
        ObligationKind::IndexBounds => "index-bounds",
        ObligationKind::SliceRange => "slice-range",
        ObligationKind::CalleeRequires(_) => "callee-requires",
        ObligationKind::Unreachable => "unreachable",
        ObligationKind::InvariantEntry => "invariant-entry",
        ObligationKind::InvariantPreserve => "invariant-preserve",
        ObligationKind::Termination => "termination",
        ObligationKind::StackDepth => "stack-depth",
        ObligationKind::Ensures => "ensures",
        ObligationKind::LawGoal => "law-goal",
        ObligationKind::Assert => "assert",
        ObligationKind::VariantEquiv => "variant-equiv",
        ObligationKind::WellFormed => "well-formed",
        ObligationKind::Refines => "refines",
        ObligationKind::TypeInvariant => "type-invariant",
        ObligationKind::InvariantExit => "invariant-exit",
        ObligationKind::ViewInjective => "view-injective",
        ObligationKind::Example => "example",
        ObligationKind::Completeness => "completeness",
    }
}

impl<'a> Elab<'a> {
    /// Pretty-prints a term of the current context.
    pub fn show_tm(&self, t: &Tm) -> String {
        // bounded: terms built by substitution share heavily (printing them
        // as trees can be exponential)
        sandblaster_kernel::syntax::printer::print_term_bounded(&self.env, &self.f.scope.names(), t, 4 * GOAL_TEXT_MAX)
    }

    /// Proves `target` (a proposition term at the current depth). The proof
    /// is placed in an irrelevant position unless `relevant`.
    pub fn prove(&mut self, kind: ObligationKind, span: Span, target: &Tm, relevant: bool) -> R<Tm> {
        self.prove_hinted(kind, span, target, vec![], relevant)
    }

    /// [`Elab::prove`] with script hints.
    pub fn prove_hinted(&mut self, kind: ObligationKind, span: Span, target: &Tm, hints: Vec<Hint>, relevant: bool) -> R<Tm> {
        // a `#[proof(complete = p)]` script (§15.5): implications among the
        // section's hypotheses and the case's facts, chained forward, are
        // irrelevant facts of the slot
        if kind == ObligationKind::Completeness && !self.f.abstracted.is_empty() && !CHAINING.with(|c| c.get()) {
            let d = self.depth();
            let tys: Vec<(u32, Tm)> = self.f.scope.facts.iter().filter(|f| !self.f.scope.hidden.contains(&f.lvl.0)).filter_map(|f| self.f.scope.fact_tys.get(&f.lvl.0).map(|t| (f.lvl.0, t.clone()))).collect();
            let derived = crate::auto::complete::forward_hints(&self.env, &self.f.scope.ctx, &tys, self.opts.complete_budget);
            if !derived.is_empty() {
                let saved = self.f.scope.clone();
                let k = derived.len() as i64;
                let pushed = derived.iter().enumerate().try_for_each(|(i, (_, ty))| self.push_fact_rel("h_mp", Rel::Irr, &sandblaster_kernel::util::shift(ty, i as i64), None, crate::prover::FactOrigin::LemmaHyp, span).map(|_| ()));
                let sh = |t: &Tm| sandblaster_kernel::util::shift(t, k);
                let hints2: Vec<Hint> = hints
                    .into_iter()
                    .map(|h| match h {
                        Hint::Lemma(t) => Hint::Lemma(sh(&t)),
                        Hint::Rewrite { eq, rev, motive } => Hint::Rewrite { eq: sh(&eq), rev, motive: motive.map(|m| sandblaster_kernel::util::shift_from(&m, k, 1)) },
                        Hint::Witness(ws) => Hint::Witness(ws.iter().map(sh).collect()),
                        Hint::Exact(t) => Hint::Exact(sh(&t)),
                        other => other,
                    })
                    .collect();
                CHAINING.with(|c| c.set(true));
                let r = pushed.and_then(|_| self.prove_hinted(kind, span, &sh(target), hints2, relevant));
                CHAINING.with(|c| c.set(false));
                self.f.scope = saved;
                let mut w = r?;
                for (i, (pf, ty)) in derived.iter().enumerate().rev() {
                    let (pf, ty) = (sandblaster_kernel::util::shift(pf, i as i64), sandblaster_kernel::util::shift(ty, i as i64));
                    w = mk::app_irr(mk::lam("h_mp", Rel::Irr, ty, w), pf);
                }
                let _ = d;
                return Ok(w);
            }
        }
        // the Nat range facts of the spec applications in the goal and the
        // facts (`0 <= f(x)` for a `Nat`-valued spec function, and the same
        // for `Nat` components of its result; `Elab::nat_range_def`):
        // irrelevant facts of the slot, applied to the range lemmas inside
        if !self.nat_ranges.is_empty() && !NAT_RANGES.with(|c| c.get()) && (self.arithmetic_goal(target) || self.ranged_guard_goal(target)) {
            let d = self.depth();
            let sc = &self.f.scope;
            let mut terms = vec![target.clone()];
            // (every recorded statement: the facts, and the path equations
            // of an `ensures` walk)
            let mut lvls: Vec<u32> = sc.fact_tys.keys().copied().filter(|l| *l < d && !sc.hidden.contains(l)).collect();
            lvls.sort();
            for l in lvls {
                terms.push(sandblaster_kernel::util::shift(&sc.fact_tys[&l], (d - l) as i64));
            }
            let found = self.nat_range_instances(&terms, 12);
            if !found.is_empty() {
                // first without them (the facts the goal had before), so a
                // goal that needs no range keeps its proof and its search —
                // except a goal that is itself a range (`0 <= f(x).a && ..`),
                // whose search without them could only fail, at a cost. That
                // attempt has a 32nd of the step budget: a goal that needs
                // a range would otherwise search to the end of its budget
                // before the ranges are bound (seconds per goal); a goal
                // whose range-free proof needs more steps gets them below,
                // when it fails with the ranges
                let (no, nd, failed) = (self.obligations.len(), self.diags.list.len(), self.f.failed);
                let ns = self.f.slot_failures.as_ref().map(|v| v.len());
                let first_try = !self.range_goal(target);
                if first_try {
                    NAT_RANGES.with(|c| c.set(true));
                    RANGE_FREE_TRY.with(|c| c.set(true));
                    let r = self.prove_hinted(kind.clone(), span, target, hints.clone(), relevant);
                    RANGE_FREE_TRY.with(|c| c.set(false));
                    NAT_RANGES.with(|c| c.set(false));
                    let p = r?;
                    if self.obligations[no..].iter().all(|o| o.proven()) {
                        return Ok(p);
                    }
                    self.obligations.truncate(no);
                    self.diags.list.truncate(nd);
                    self.f.failed = failed;
                    if let (Some(v), Some(n)) = (self.f.slot_failures.as_mut(), ns) {
                        v.truncate(n);
                    }
                }
                let saved = self.f.scope.clone();
                let k = found.len() as i64;
                let pushed = found.iter().enumerate().try_for_each(|(i, (ty, _))| self.push_fact_rel("h_range", Rel::Irr, &sandblaster_kernel::util::shift(ty, i as i64), None, crate::prover::FactOrigin::TypeBound, span).map(|_| ()));
                let sh = |t: &Tm| sandblaster_kernel::util::shift(t, k);
                let hints2: Vec<Hint> = hints
                    .clone()
                    .into_iter()
                    .map(|h| match h {
                        Hint::Lemma(t) => Hint::Lemma(sh(&t)),
                        Hint::Rewrite { eq, rev, motive } => Hint::Rewrite { eq: sh(&eq), rev, motive: motive.map(|m| sandblaster_kernel::util::shift_from(&m, k, 1)) },
                        Hint::Witness(ws) => Hint::Witness(ws.iter().map(sh).collect()),
                        Hint::Exact(t) => Hint::Exact(sh(&t)),
                        other => other,
                    })
                    .collect();
                NAT_RANGES.with(|c| c.set(true));
                let r = pushed.and_then(|_| self.prove_hinted(kind.clone(), span, &sh(target), hints2, relevant));
                NAT_RANGES.with(|c| c.set(false));
                self.f.scope = saved;
                let w = r?;
                // failed with the ranges: the range-free attempt with the
                // whole budget; if that fails too, the failure reported is
                // the one with the ranges
                if first_try && !self.obligations[no..].iter().all(|o| o.proven()) {
                    let (o2, d2, f2) = (self.obligations.split_off(no), self.diags.list.split_off(nd), self.f.failed);
                    let s2 = match (self.f.slot_failures.as_mut(), ns) {
                        (Some(v), Some(n)) => Some(v.split_off(n)),
                        _ => None,
                    };
                    self.f.failed = failed;
                    NAT_RANGES.with(|c| c.set(true));
                    let r = self.prove_hinted(kind, span, target, hints, relevant);
                    NAT_RANGES.with(|c| c.set(false));
                    let p = r?;
                    if self.obligations[no..].iter().all(|o| o.proven()) {
                        return Ok(p);
                    }
                    self.obligations.truncate(no);
                    self.diags.list.truncate(nd);
                    self.obligations.extend(o2);
                    self.diags.list.extend(d2);
                    self.f.failed = f2;
                    if let (Some(v), Some(s2)) = (self.f.slot_failures.as_mut(), s2) {
                        if let Some(n) = ns {
                            v.truncate(n);
                        }
                        v.extend(s2);
                    }
                }
                // unused range facts leave no trace in the proof (it may
                // sit in a statement)
                if matches!(&*w, Term::Erased) || !(0..k as u32).any(|i| sandblaster_kernel::util::occurs(&w, i)) {
                    return Ok(sandblaster_kernel::util::shift(&w, -k));
                }
                let mut w = w;
                for (i, (ty, pf)) in found.iter().enumerate().rev() {
                    let (pf, ty) = (sandblaster_kernel::util::shift(pf, i as i64), sandblaster_kernel::util::shift(ty, i as i64));
                    w = mk::app_irr(mk::lam("h_range", Rel::Irr, ty, w), pf);
                }
                return Ok(w);
            }
        }
        // hint facts (`Scope::hint_facts`: facts over `#[ghost]` parameters,
        // invariant facts in pure contexts, §15.3): bound for the prover at
        // the end of the context, then abstracted and applied to their
        // proofs inside the slot
        if !self.f.scope.hint_facts.is_empty() {
            let facts = std::mem::take(&mut self.f.scope.hint_facts);
            let saved = self.f.scope.clone();
            let mut tys = Vec::new();
            let mut pfs = Vec::new();
            let mut names = Vec::new();
            let pushed = (|| -> R<()> {
                for hf in &facts {
                    let dd = self.depth();
                    let (t, p) = (hf.ty.at(dd), hf.proof.at(dd));
                    self.push_fact_rel(hf.name, sandblaster_kernel::term::Rel::Rel, &t, None, hf.origin.clone(), span)?;
                    tys.push(t);
                    pfs.push(p);
                    names.push(hf.name);
                }
                Ok(())
            })();
            let k = facts.len() as i64;
            let sh = |t: &Tm| sandblaster_kernel::util::shift(t, k);
            let hints2: Vec<Hint> = hints
                .into_iter()
                .map(|h| match h {
                    Hint::Lemma(t) => Hint::Lemma(sh(&t)),
                    Hint::Rewrite { eq, rev, motive } => Hint::Rewrite { eq: sh(&eq), rev, motive: motive.map(|m| sandblaster_kernel::util::shift_from(&m, k, 1)) },
                    Hint::Witness(ws) => Hint::Witness(ws.iter().map(sh).collect()),
                    Hint::Exact(t) => Hint::Exact(sh(&t)),
                    other => other,
                })
                .collect();
            let r = match pushed {
                Ok(()) => self.prove_hinted(kind, span, &sh(target), hints2, relevant),
                Err(e) => Err(e),
            };
            self.f.scope = saved;
            self.f.scope.hint_facts = facts;
            let mut w = r?;
            for ((t, p), n) in tys.into_iter().zip(pfs).zip(names).rev() {
                w = mk::app(mk::lam(n, sandblaster_kernel::term::Rel::Rel, t, w), p);
            }
            return Ok(w);
        }
        let id = self.obligations.len() as u32;
        // targets built by substitution may contain instantiated proofs whose
        // certificates no longer fit (see `recert`)
        let target_owned = super::recert::recertify(&self.env, &self.f.scope.ctx, target);
        let target = &target_owned;
        let tv = self.eval(target)?;
        let hinted = !hints.is_empty();
        // fast path: an equation whose sides convert
        if let Value::Eq { lhs, rhs, .. } = &*tv {
            let mut b = self.budget();
            if self.env.conv(Lvl(self.depth()), lhs, rhs, &mut b).unwrap_or(false) {
                let proof = match &**target {
                    Term::Eq { ty, lhs, .. } => mk::refl(ty.clone(), lhs.clone()),
                    _ => {
                        let Value::Eq { ty, lhs, .. } = &*tv else { unreachable!() };
                        mk::refl(self.quote(ty, None), self.quote(lhs, None))
                    }
                };
                self.record(id, kind, span, OblStatus::Proven { by: "eval".into() }, hinted, String::new());
                return Ok(proof);
            }
        }
        let (gctx, gfacts) = self.prover_view();
        let goal = Goal { id: ObligationId(id), kind: kind.clone(), span, ctx: gctx, facts: gfacts, target: tv.clone(), hints };
        let mut b = self.budget();
        if RANGE_FREE_TRY.with(|c| c.get()) {
            b.steps /= 32;
        }
        if TRY_BUDGET.with(|c| c.get()) > 0 {
            b.steps /= 8;
        }
        // an inner attempt of a lockstep (`elab::refines`): a fraction of the
        // budget (the lockstep decomposes a goal the prover does not close
        // quickly)
        let div = super::lockstep::PROVER_DIV.with(|c| c.get());
        if div > 1 {
            b.steps /= div;
        }
        let hidden = self.f.scope.hidden.clone();
        super::basic::set_goal_terms(Some(super::basic::GoalTerms { id, target: target.clone(), facts: self.f.scope.fact_tys.iter().filter(|(l, _)| !hidden.contains(l)).map(|(l, t)| (*l, t.clone())).collect() }));
        let trace = std::env::var_os("SANDBLASTER_TRACE_OBL").is_some();
        let t0 = std::time::Instant::now();
        let trips0 = crate::auto::meter::trip_count();
        let mut res = self.prover.prove(&self.env, &goal, &mut b);
        // a proof the kernel rejects is not a result: the provers after the
        // one that returned it get the goal (the fast `basic` prover can
        // return a term with an `Erased` placeholder where `auto` finds one
        // that checks)
        while let (Ok(p), Some(i)) = (&res, self.prover.last) {
            if i + 1 >= self.prover.provers.len() {
                break;
            }
            let p2 = super::recert::recertify(&self.env, &self.f.scope.ctx, p);
            if self.check_proof(&p2, target, relevant).is_ok() {
                break;
            }
            if relevant && let Some(q) = self.repair_relevance(&p2, target) {
                res = Ok(q);
                break;
            }
            let saved = self.prover.start;
            self.prover.start = i + 1;
            let mut b2 = self.budget();
            let r2 = self.prover.prove(&self.env, &goal, &mut b2);
            self.prover.start = saved;
            match r2 {
                Ok(p3) => res = Ok(p3),
                Err(_) => {
                    // keep the rejected proof: its rejection is the report
                    self.prover.last = Some(i);
                    break;
                }
            }
        }
        let tripped = crate::auto::meter::trip_count() > trips0;
        super::basic::set_goal_terms(None);
        // the hidden facts belong to this goal only
        super::set_hidden_facts(Vec::new());
        let t1 = t0.elapsed();
        let failure = match res {
            Ok(p) => match {
                let p2 = super::recert::recertify(&self.env, &self.f.scope.ctx, &p);
                let r = self.check_proof(&p2, target, relevant);
                // (a proof valid only in an irrelevant position, promoted)
                let (r, p2) = match r {
                    Err(e) if relevant => match self.repair_relevance(&p2, target) {
                        Some(q) => (Ok(()), q),
                        None => (Err(e), p2),
                    },
                    r => (r, p2),
                };
                if trace {
                    eprintln!("obl {id} {} in {}: proven by {} in {:?}, proof size {}, checked in {:?}: {}", kind_name(&kind), self.f.name, self.prover.last_name(), t1, super::tm::size(&p2), t0.elapsed() - t1, r.is_ok());
                }
                r.map(|_| p2)
            } {
                Ok(p) => {
                    let by = self.prover.last_name();
                    self.record(id, kind, span, OblStatus::Proven { by }, hinted, String::new());
                    return Ok(p);
                }
                Err(msg) => {
                    let pt: String = self.show_tm(&p).chars().take(20000).collect();
                    if let Ok(dir) = std::env::var("SANDBLASTER_DUMP_PROOFS") {
                        let _ = std::fs::write(format!("{dir}/proof-{id}.txt"), self.show_tm(&p));
                    }
                    AutoFailure { tried: vec![format!("the prover returned a proof the kernel rejects: {msg}"), format!("proof: {pt}")], ..Default::default() }
                }
            },
            Err(f) => {
                if trace {
                    eprintln!("obl {id} {} in {}: failed after {:?}", kind_name(&kind), self.f.name, t1);
                }
                f
            }
        };
        if tripped {
            // a safety net (wall clock, memory) stopped the search: a
            // resource failure of the build, not a proof result (§15.8)
            self.resource_failure(id, kind, span, target, failure, hinted);
            return Ok(Rc::new(Term::Erased));
        }
        // a counterexample tells a false obligation from one not proven
        // (`crate::refute`; inert unless enabled)
        let failure = crate::refute::annotate(&self.env, &self.f.scope.ctx, target, self.f.scope.hint_facts.is_empty(), failure);
        self.fail_obligation(id, kind, span, target, failure, hinted);
        Ok(Rc::new(Term::Erased))
    }

    /// The context and facts shown to the prover. Facts superseded by a
    /// refined copy ([`super::Scope::hidden`]) are left out of the fact list
    /// and registered with [`crate::elab::set_hidden_facts`] so the provers
    /// skip them; they keep their types (proof terms inside the goal may
    /// refer to them).
    fn prover_view(&self) -> (sandblaster_kernel::api::Ctx, Vec<crate::prover::FactRef>) {
        let sc = &self.f.scope;
        super::set_hidden_facts(sc.hidden.iter().copied().collect());
        if sc.hidden.is_empty() {
            return (sc.ctx.clone(), sc.facts.clone());
        }
        let facts = sc.facts.iter().filter(|f| !sc.hidden.contains(&f.lvl.0)).cloned().collect();
        (sc.ctx.clone(), facts)
    }

    /// A prover result for a relevant slot that checks only in an
    /// irrelevant position — it closes the goal with an irrelevant fact
    /// whose statement is no equation (a match-shaped hypothesis of
    /// `use_hyp`, a conjunction of such) — made relevant by promotion when
    /// the target carries no information ([`Elab::promote_irr`]: equations,
    /// `Unit`, `Empty`, `Π`/`Σ` of them, propositions by cases).
    fn repair_relevance(&self, p: &Tm, target: &Tm) -> Option<Tm> {
        if super::tm::has_erased(p) || self.check_proof(p, target, false).is_err() {
            return None;
        }
        let q = self.promote_irr(target, p, 16)?;
        self.check_proof(&q, target, true).ok().map(|_| q)
    }

    /// Kernel check of a prover result in the goal context.
    pub(super) fn check_proof(&self, p: &Tm, target: &Tm, relevant: bool) -> Result<(), String> {
        if !self.opts.check_proofs || super::tm::has_erased(target) {
            // an earlier obligation of this definition failed (its placeholder
            // is in the target): the definition is not submitted anyway
            return Ok(());
        }
        let tv = self.eval(target).map_err(|e| e.msg)?;
        self.check_proof_in(&self.f.scope.ctx, p, target, &tv, relevant)
    }

    /// Kernel check of `p : target` (`tv` its value) in `ctx`, in a relevant
    /// or an irrelevant position.
    pub(super) fn check_proof_in(&self, ctx: &sandblaster_kernel::api::Ctx, p: &Tm, target: &Tm, tv: &sandblaster_kernel::value::V, relevant: bool) -> Result<(), String> {
        // generous, but bounded well below a whole definition's budget: a
        // proof that takes longer to check is treated as a failure
        let mut b = Budget { steps: self.opts.goal_budget.saturating_mul(20) };
        if relevant {
            return self.env.check(ctx, p, tv, &mut b).map_err(|e| e.to_string());
        }
        // an irrelevant slot: check `let .h : P = p; tt : Unit`
        let mut wrapped = mk::let_("h", Rel::Irr, target.clone(), p.clone(), self.unit_val());
        if !self.f.scope.ghost_locals.is_empty() {
            // `P` may mention the (irrelevant) ghost bundle, usable only in
            // an irrelevant position (§15.3): check it inside one
            let unit_ty = mk::ind(self.p.unit, vec![]);
            wrapped = mk::let_("g", Rel::Irr, unit_ty, wrapped, self.unit_val());
        }
        let unit = self.eval(&mk::ind(self.p.unit, vec![])).map_err(|e| e.msg)?;
        self.env.check(ctx, &wrapped, &unit, &mut b).map_err(|e| e.to_string())
    }

    /// Runs the prover chain on an explicit goal (not the current scope's):
    /// the levels in `hidden` are not shown to the provers, `terms` are the
    /// goal's terms for the basic prover.
    pub(super) fn run_chain(&mut self, goal: &Goal, hidden: Vec<u32>, terms: super::basic::GoalTerms) -> Result<Tm, AutoFailure> {
        let mut b = self.budget();
        super::set_hidden_facts(hidden);
        super::basic::set_goal_terms(Some(terms));
        let res = self.prover.prove(&self.env, goal, &mut b);
        super::basic::set_goal_terms(None);
        super::set_hidden_facts(Vec::new());
        res
    }

    /// Records a failed obligation and its diagnostic.
    /// An obligation whose search a safety net stopped (the per-goal
    /// deadline, the memory limits; `crate::auto::meter`): the build fails
    /// with `error[resource]` — a failure of its resources, never a proof
    /// result (DESIGN.md §15.8: outcomes are decided by step budgets only).
    pub fn resource_failure(&mut self, id: u32, kind: ObligationKind, span: Span, target: &Tm, failure: AutoFailure, hinted: bool) {
        self.f.failed = true;
        let goal_text = trunc(self.show_tm(target));
        let why: Vec<String> = failure.tried.iter().filter(|t| t.contains("deadline exceeded") || t.contains("memory") || t.contains("heap cap")).cloned().collect();
        let mut d = Diagnostic::error(DiagKind::Resource, span, format!("a resource safety net stopped the proof of [{}] in `{}`: the build failed for resources; this is not a proof result", kind_name(&kind), self.f.name))
            .note("proofs are decided by step budgets only (DESIGN.md §15.8); the wall-clock deadline and the memory limits are safety nets set well above them — rerun on a less loaded machine, or raise SANDBLASTER_GOAL_TIMEOUT_MS / SANDBLASTER_MEM_LIMIT_GB (they change resource limits only, never an outcome)");
        for w in why.iter().take(2) {
            d = d.note(format!("tripped: {}", trunc(w.clone())));
        }
        d.goal = Some(format!("goal: {goal_text}"));
        self.diags.push(d);
        self.record(id, kind, span, OblStatus::Failed(failure), hinted, goal_text);
    }

    pub fn fail_obligation(&mut self, id: u32, kind: ObligationKind, span: Span, target: &Tm, failure: AutoFailure, hinted: bool) {
        self.f.failed = true;
        if self.f.slot_failures.is_some() {
            let g = self.surface(target);
            if let Some(v) = self.f.slot_failures.as_mut() {
                v.push((span, kind.clone(), g));
            }
        }
        let goal_text = trunc(self.show_tm(target));
        let mut d = Diagnostic::error(DiagKind::Obligation, span, format!("unproven obligation [{}] in `{}`", kind_name(&kind), self.f.name));
        if self.arithmetic_goal(target)
            && let Some(n) = self.nat_range_note(target)
        {
            d = d.note(n);
        }
        let mut goal = format!("goal: {goal_text}");
        // a refinement goal in the specification's syntax (§15.10): the
        // kernel form stays in the record
        let facts: Vec<String> = if kind == ObligationKind::Refines {
            goal = format!("goal: {}", self.surface(target));
            let d0 = self.depth();
            let mut fs: Vec<String> = self
                .f
                .scope
                .facts
                .iter()
                .filter(|f| !self.f.scope.hidden.contains(&f.lvl.0))
                .filter_map(|f| {
                    let l = f.lvl.0;
                    let t = self.f.scope.fact_tys.get(&l)?;
                    let name = self.f.scope.ctx.entries.get(l as usize)?.name.to_string();
                    Some(format!("{name} : {}", self.surface(&sandblaster_kernel::util::shift(t, (d0 - l) as i64))))
                })
                .collect();
            // the path conditions of the branch (the walk's equation binders)
            let listed: std::collections::HashSet<u32> = self.f.scope.facts.iter().map(|f| f.lvl.0).collect();
            let mut path: Vec<String> = Vec::new();
            for (l, e) in self.f.scope.ctx.entries.iter().enumerate().rev() {
                if path.len() >= 8 {
                    break;
                }
                if e.rel != sandblaster_kernel::term::Rel::Irr || listed.contains(&(l as u32)) || !matches!(&*e.ty, Value::Eq { .. }) {
                    continue;
                }
                let t = self.quote(&e.ty, None);
                path.push(format!("{} (path)", self.surface(&t)));
            }
            path.reverse();
            fs.extend(path);
            fs
        } else if failure.facts.is_empty() {
            self.f.scope.facts.iter().filter_map(|f| self.f.scope.ctx.entries.get(f.lvl.0 as usize).map(|e| trunc(format!("{} : {}", e.name, super::show::value(&self.env, &self.f.scope.names(), &e.ty, GOAL_TEXT_MAX))))).collect()
        } else {
            failure.facts.iter().cloned().map(trunc).collect()
        };
        for f in &facts {
            goal.push_str(&format!("\n  fact: {f}"));
        }
        d.goal = Some(goal);
        for s in failure.stuck.iter().take(8) {
            d = d.note(format!("stuck: {}", trunc(s.clone())));
        }
        for t in failure.tried.iter().take(12) {
            d = d.note(format!("tried: {}", trunc(t.clone())));
        }
        if kind == ObligationKind::InvariantExit {
            d = d.note(INVARIANT_EXIT_NOTE);
        }
        self.diags.push(d);
        self.record(id, kind, span, OblStatus::Failed(failure), hinted, goal_text);
    }

    /// A kernel term of the current context in surface syntax (bounded),
    /// for refinement diagnostics ([`crate::deelab::KernelShow`]).
    pub fn surface(&self, t: &Tm) -> String {
        let names: Vec<String> = self.f.scope.names().iter().map(|n| n.to_string()).collect();
        let s = crate::deelab::KernelShow::new(&self.env, names).with_ctx(&self.f.scope.ctx).show(t);
        if s.chars().count() > 1500 { format!("{}…", s.chars().take(1500).collect::<String>()) } else { s }
    }

    pub fn record(&mut self, id: u32, kind: ObligationKind, span: Span, status: OblStatus, hinted: bool, goal: String) {
        self.obligations.push(ObligationRecord { id, kind, span, def: self.f.name.clone(), status, hinted, goal });
    }

    /// An open (`todo()`) obligation.
    pub fn todo_obligation(&mut self, span: Span, target: &Tm) {
        self.f.failed = true;
        let id = self.obligations.len() as u32;
        let goal = trunc(self.show_tm(target));
        let mut d = Diagnostic::error(DiagKind::Obligation, span, format!("`todo()` leaves the goal open in `{}`", self.f.name));
        d.goal = Some(format!("goal: {goal}"));
        self.diags.push(d);
        self.record(id, ObligationKind::LawGoal, span, OblStatus::Todo, true, goal);
    }
}
