//! The proof state of one branch of the search (DESIGN.md §7.2, §8.1).
//!
//! Facts are **context entries**, exactly as the elaborator provides them:
//! a fact is a binder of the kernel [`Ctx`] (by level) whose type is a
//! proposition. Everything `auto` derives (conjuncts, rewritten facts,
//! decided comparisons, lemma and axiom instances) is pushed as a new
//! irrelevant binder and recorded as a *wrapper* (`let .h : P = proof;`),
//! so later steps refer to it by level and de Bruijn shifting is automatic.
//! Goal-level introductions (`→`/`∀` targets) are recorded as `λ` wrappers.
//! [`St::finish`] closes the wrappers around the proof of the final target
//! (dropping lets that are not used).
//!
//! A state is cheap to clone (the context is shared), so alternatives
//! (`∨` sides, candidate case splits) are explored on clones; a case split
//! starts a child frame per arm ([`St::child`]).

use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry, Env};
use sandblaster_kernel::term::{GlobalId, IndId, Lvl, Name, Rel, Term, Tm};
use sandblaster_kernel::value::{Budget, EnvEntry, EvalError, V, VEnv};

use super::util::{fold_array_eta, occurs, shift, var_at, venv_push};
use crate::prover::FactOrigin;

/// Where a fact of the search came from.
#[derive(Clone, Debug)]
pub enum Origin {
    /// A binder of the goal's context (with the elaborator's origin, if the
    /// goal listed it).
    Goal(Option<FactOrigin>),
    /// A path equation of a case split made by `auto`.
    Split,
    /// A binder introduced for a `→`/`∀` target.
    Intro,
    /// Derived by a named step.
    Derived(&'static str),
    /// A `Hint::Lemma` instance.
    Hint,
}

/// A fact: a context binder whose type is a proposition.
#[derive(Clone, Debug)]
pub struct Fact {
    pub lvl: u32,
    pub ty: V,
    pub origin: Origin,
}

#[derive(Clone, Debug)]
enum Wrap {
    Let { name: Name, ty: Tm, val: Tm },
    Lam { name: Name, rel: Rel, dom: Tm },
}

/// One branch of the search.
#[derive(Clone)]
pub struct St {
    pub ctx: Ctx,
    pub venv: VEnv,
    pub facts: Vec<Fact>,
    wraps: Vec<Wrap>,
    /// `facts[..sat]` have been saturated (§8.1 step 4).
    pub sat: usize,
    /// Facts (by level) already used for a disequality split.
    pub split_diseqs: Vec<u32>,
    /// Scrutinees already split on in this branch.
    pub split_vals: Vec<V>,
    /// Facts derived by rewriting in this branch.
    pub fact_rewrites: u32,
    /// Rule instances added as facts in this branch.
    pub instances: usize,
    /// Rewrites and unfoldings performed on this path.
    pub rewrites: u32,
    pub deltas: u32,
    /// Remaining case-split depth.
    pub depth_left: u32,
    /// Counter for fresh binder names.
    pub fresh: u32,
    /// The goal's rewrite / unfold hints were applied on this branch.
    pub hints_done: bool,
    /// Equations between two stuck terms (by level) already used to
    /// rewrite the target in this branch.
    pub used_eqs: Vec<u32>,
    /// The sides `(from, to)` of those equations: a later fact with the
    /// same equation (a copy made by a generalizing rewrite, or its
    /// reverse) is not used again.
    pub used_eq_sides: Vec<(V, V)>,
    /// (fact, rule) pairs (by level) already rewritten in this branch: a
    /// fact is rewritten by a rule once, whichever of the two is saturated
    /// first (a chain `a && (b && ..)` otherwise doubles its facts at every
    /// determined conjunct).
    pub rewritten: Vec<(u32, u32)>,
    /// Scrutinees the fact simplifier tried to decide by linear arithmetic
    /// on this branch ([`super::rewrite`] `simp_fact`, bounded).
    pub simp_lin: u32,
    /// Scrutinees the simplifier could not decide, with the number of facts
    /// at the time (retried only once the branch has more facts).
    pub simp_undecided: Vec<(V, usize)>,
    /// Variables (by level) replaced by their definitions in the target
    /// ([`super::search::Engine::expanded_close`]): the fact equations that
    /// rewrite a term back to one of them are not used on this branch.
    pub expanded: Vec<u32>,
    /// `seq::index` and `List`, for folding array eta expansions in quoted
    /// terms ([`super::util::fold_array_eta`]).
    eta: Option<(GlobalId, IndId)>,
}

impl St {
    /// The root state of a goal.
    pub fn new(env: &Env, ctx: &Ctx, depth_left: u32) -> St {
        St {
            ctx: ctx.clone(),
            venv: env.ctx_venv(ctx),
            facts: Vec::new(),
            wraps: Vec::new(),
            sat: 0,
            split_diseqs: Vec::new(),
            split_vals: Vec::new(),
            fact_rewrites: 0,
            instances: 0,
            rewrites: 0,
            deltas: 0,
            depth_left,
            fresh: 0,
            hints_done: false,
            used_eqs: Vec::new(),
            used_eq_sides: Vec::new(),
            rewritten: Vec::new(),
            expanded: Vec::new(),
            simp_lin: 0,
            simp_undecided: Vec::new(),
            eta: env.lookup_global("seq::index").zip(env.lookup_ind("List")),
        }
    }

    pub fn depth(&self) -> u32 {
        self.ctx.depth().0
    }

    /// A new frame at the current point (its wrappers are closed by its own
    /// [`St::finish`]).
    pub fn child(&self) -> St {
        let mut c = self.clone();
        c.wraps.clear();
        c
    }

    /// The term of the context variable at `lvl`.
    pub fn var(&self, lvl: u32) -> Tm {
        var_at(self.depth(), lvl)
    }

    /// Evaluate a term in this state.
    pub fn eval(&self, env: &Env, t: &Tm, b: &mut Budget) -> Result<V, EvalError> {
        env.eval(&self.venv, Lvl(self.depth()), t, b)
    }

    /// Quote a value (typed read-back, so pairs get their Σ types), with
    /// array eta expansions folded back ([`super::util::fold_array_eta`]).
    /// The read-back is charged to the goal ([`super::meter::charge_quote`]);
    /// a value too large for the remaining budget is not read back: the
    /// result is `Erased` and the goal is exhausted.
    pub fn quote(&self, env: &Env, v: &V) -> Tm {
        if !super::meter::charge_quote(env, &self.ctx, v, None, true) {
            return Rc::new(Term::Erased);
        }
        self.fold_eta(env, env.quote_typed(&self.ctx, v, None, false))
    }

    /// Quote a value at a known type (charged like [`St::quote`]).
    pub fn quote_at(&self, env: &Env, v: &V, ty: &V) -> Tm {
        if !super::meter::charge_quote(env, &self.ctx, v, Some(ty), true) {
            return Rc::new(Term::Erased);
        }
        self.fold_eta(env, env.quote_typed(&self.ctx, v, Some(ty), false))
    }

    fn fold_eta(&self, env: &Env, t: Tm) -> Tm {
        let t = super::util::kernel_friendly(env, &t);
        match self.eta {
            Some((index, list)) => fold_array_eta(&t, index, list),
            None => t,
        }
    }

    fn fresh_name(&mut self, base: &str) -> Name {
        self.fresh += 1;
        Rc::from(format!("{base}{}", self.fresh))
    }

    /// Push a context binder without a wrapper (match-arm fields). Returns
    /// the environment entry (eta-expanded for arrays).
    pub fn push_raw(&mut self, env: &Env, name: Name, rel: Rel, ty: V) -> EnvEntry {
        let d = self.depth();
        let e = env.fresh_var(Lvl(d), rel, &ty);
        self.ctx = self.ctx.push(CtxEntry { name, rel, ty, def: None });
        self.venv = venv_push(&self.venv, e.clone());
        e
    }

    /// Push a derived fact `let .h : ty = proof;` (proof at the current
    /// depth). Returns its level.
    pub fn push_fact(&mut self, env: &Env, ty: V, proof: Tm, origin: Origin) -> u32 {
        let ty_tm = self.quote(env, &ty);
        let name = self.fresh_name("h");
        let lvl = self.depth();
        self.wraps.push(Wrap::Let { name: name.clone(), ty: ty_tm, val: proof });
        self.push_raw(env, name, Rel::Irr, ty.clone());
        self.facts.push(Fact { lvl, ty, origin });
        lvl
    }

    /// Push a λ binder (for a `Π` target); if it is a proposition it also
    /// becomes a fact. Returns the entry.
    pub fn push_lam(&mut self, env: &Env, name: Name, rel: Rel, ty: V, is_prop: bool) -> EnvEntry {
        let dom = self.quote(env, &ty);
        let lvl = self.depth();
        self.wraps.push(Wrap::Lam { name: name.clone(), rel, dom });
        let e = self.push_raw(env, name, rel, ty.clone());
        if is_prop {
            self.facts.push(Fact { lvl, ty, origin: Origin::Intro });
        }
        e
    }

    /// A snapshot of the facts for a scan (charged per fact to the goal,
    /// [`super::meter`]).
    pub fn scan_facts(&self) -> Vec<Fact> {
        super::meter::spend(1 + self.facts.len() as u64);
        self.facts.clone()
    }

    /// Register an existing context binder as a fact.
    pub fn add_ctx_fact(&mut self, lvl: u32, ty: V, origin: Origin) {
        self.facts.push(Fact { lvl, ty, origin });
    }

    /// Close this frame's wrappers around `body` (a term at the current
    /// depth). Unused lets are dropped.
    pub fn finish(&self, mut body: Tm) -> Tm {
        for w in self.wraps.iter().rev() {
            body = match w {
                Wrap::Let { name, ty, val } => {
                    if occurs(&body, 0) {
                        Rc::new(Term::Let { name: name.clone(), rel: Rel::Irr, ty: ty.clone(), val: val.clone(), body })
                    } else {
                        shift(&body, -1)
                    }
                }
                Wrap::Lam { name, rel, dom } => Rc::new(Term::Lam { name: name.clone(), rel: *rel, dom: dom.clone(), body }),
            };
        }
        body
    }

    /// Names of the context binders (for printing).
    pub fn names(&self) -> Vec<Name> {
        self.ctx.entries.iter().map(|e| e.name.clone()).collect()
    }
}
