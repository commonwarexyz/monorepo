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
use sandblaster_kernel::term::{GlobalId, Idx, IndId, Lvl, Name, Rel, Term, Tm};
use sandblaster_kernel::value::{Budget, EnvEntry, EvalError, V, VEnv};

use super::util::{fold_array_eta, var_at, venv_push};
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
    /// Hardware models unfolded at a lane on this path ([`super::lanes`]).
    pub lanes: u32,
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
    /// Equations between two stuck terms (by level, and whether used right
    /// to left) that aligned an argument of the target with an equation's
    /// side in this branch (`align_with_equations`, `super::rewrite`).
    pub aligned: Vec<(u32, bool)>,
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
            lanes: 0,
            depth_left,
            fresh: 0,
            hints_done: false,
            used_eqs: Vec::new(),
            used_eq_sides: Vec::new(),
            aligned: Vec::new(),
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

    /// [`St::push_fact`] with the fact's type term given (`ty_tm`, at the
    /// current depth, convertible with `ty`) instead of read back from its
    /// value: a statement built from the goal's terms stays as small as
    /// those terms ([`super::terms`]).
    pub fn push_fact_tm(&mut self, env: &Env, ty: V, ty_tm: Tm, proof: Tm, origin: Origin) -> u32 {
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
    /// depth). Unused lets are dropped ([`close_wraps`]).
    pub fn finish(&self, body: Tm) -> Tm {
        close_wraps(&self.wraps, body)
    }

    /// Names of the context binders (for printing).
    pub fn names(&self) -> Vec<Name> {
        self.ctx.entries.iter().map(|e| e.name.clone()).collect()
    }
}

/// `body` (a term under the wrappers) closed by the wrappers, outermost
/// first; a `let` whose variable nothing uses is dropped.
///
/// Linear in the size of the result: one pass finds the wrappers that are
/// used (by the body, or by the type or value of a kept wrapper inside
/// them), one pass per kept term renumbers its variables. (One `occurs`
/// test and one shift of the whole body per wrapper, the obvious loop, is
/// quadratic: a proof of tens of thousands of nodes under the dozens of
/// facts a search derives, most of them unused, cost more steps than the
/// search that found it, and the goal ran out of budget after its proof
/// was built.)
fn close_wraps(wraps: &[Wrap], body: Tm) -> Tm {
    let n = wraps.len();
    if n == 0 {
        return body;
    }
    // `used[j]`: wrapper `j`'s variable occurs in the body or in a kept
    // wrapper inside it (a term under the wrappers `0..m` refers to wrapper
    // `m - 1 - f` by the free index `f < m`)
    let mut used = vec![false; n];
    mark_free_wraps(&body, &mut used);
    for j in (0..n).rev() {
        match &wraps[j] {
            Wrap::Let { ty, val, .. } if used[j] => {
                mark_free_wraps(ty, &mut used[..j]);
                mark_free_wraps(val, &mut used[..j]);
            }
            Wrap::Let { .. } => {}
            Wrap::Lam { dom, .. } => mark_free_wraps(dom, &mut used[..j]),
        }
    }
    let keep: Vec<bool> = (0..n).map(|j| used[j] || matches!(wraps[j], Wrap::Lam { .. })).collect();
    // `kept[m]`: the kept wrappers among `0..m`
    let mut kept = vec![0u32; n + 1];
    for j in 0..n {
        kept[j + 1] = kept[j] + keep[j] as u32;
    }
    // a term under the wrappers `0..m`, its variables renumbered for the kept
    // wrappers (a wrapper it refers to is kept; a variable of the enclosing
    // context moves down by the dropped wrappers)
    let renumber = |t: &Tm, m: usize| -> Tm {
        if kept[m] == m as u32 {
            return t.clone();
        }
        crate::elab::tm::map_post(t, 0, &mut |node, depth| {
            Some(match &*node {
                Term::Var(Idx(i)) if *i >= depth => {
                    let f = (*i - depth) as usize;
                    let f2 = if f < m { kept[m] - kept[m - f] } else { (f - m) as u32 + kept[m] };
                    Rc::new(Term::Var(Idx(f2 + depth)))
                }
                _ => node,
            })
        })
        .expect("renumber")
    };
    let mut out = renumber(&body, n);
    for j in (0..n).rev() {
        if !keep[j] {
            continue;
        }
        out = match &wraps[j] {
            Wrap::Let { name, ty, val } => Rc::new(Term::Let { name: name.clone(), rel: Rel::Irr, ty: renumber(ty, j), val: renumber(val, j), body: out }),
            Wrap::Lam { name, rel, dom } => Rc::new(Term::Lam { name: name.clone(), rel: *rel, dom: renumber(dom, j), body: out }),
        };
    }
    out
}

/// Marks in `used` the wrappers a term under the wrappers `0..used.len()`
/// refers to (the free index `f` names wrapper `used.len() - 1 - f`; larger
/// indices are the enclosing context). One pass over the term graph,
/// charged to the goal ([`super::meter`]), that stops once every wrapper is
/// marked (so it never costs more than the obvious loop's `occurs` tests).
fn mark_free_wraps(t: &Tm, used: &mut [bool]) {
    let m = used.len() as u32;
    let mut unmarked = used.iter().filter(|u| !**u).count();
    if unmarked == 0 {
        return;
    }
    crate::elab::tm::any_node_depth(t, &mut |node, depth| {
        if let Term::Var(Idx(i)) = node
            && *i >= depth
            && *i - depth < m
        {
            let j = (m - 1 - (*i - depth)) as usize;
            if !used[j] {
                used[j] = true;
                unmarked -= 1;
            }
        }
        unmarked == 0
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandblaster_kernel::util::mk;

    /// The obvious loop, the reference: one `occurs` test and one shift of
    /// the whole body per wrapper.
    fn close_naive(wraps: &[Wrap], mut body: Tm) -> Tm {
        for w in wraps.iter().rev() {
            body = match w {
                Wrap::Let { name, ty, val } => {
                    if super::super::util::occurs(&body, 0) {
                        Rc::new(Term::Let { name: name.clone(), rel: Rel::Irr, ty: ty.clone(), val: val.clone(), body })
                    } else {
                        super::super::util::shift(&body, -1)
                    }
                }
                Wrap::Lam { name, rel, dom } => Rc::new(Term::Lam { name: name.clone(), rel: *rel, dom: dom.clone(), body }),
            };
        }
        body
    }

    /// A deterministic pseudo-random source.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self, n: u64) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) % n.max(1)
        }
    }

    /// A term over `ctx` free variables, with binders of its own.
    fn term(r: &mut Lcg, ctx: u32, size: u32) -> Tm {
        if size <= 1 || r.next(4) == 0 {
            return if ctx > 0 && r.next(3) != 0 { mk::var(r.next(ctx as u64) as u32) } else { mk::ty() };
        }
        match r.next(3) {
            0 => mk::app(term(r, ctx, size / 2), term(r, ctx, size / 2)),
            1 => mk::lam("x", Rel::Rel, term(r, ctx, size / 3), term(r, ctx + 1, size / 2)),
            _ => mk::let_("y", Rel::Irr, term(r, ctx, size / 3), term(r, ctx, size / 3), term(r, ctx + 1, size / 2)),
        }
    }

    /// The wrappers of a search over an enclosing context of `outer`
    /// variables: mostly lets, some λs.
    fn wraps(r: &mut Lcg, outer: u32, n: u32) -> Vec<Wrap> {
        (0..n)
            .map(|j| {
                let ctx = outer + j;
                if r.next(4) == 0 {
                    Wrap::Lam { name: mk::name("a"), rel: Rel::Rel, dom: term(r, ctx, 4) }
                } else {
                    Wrap::Let { name: mk::name("h"), ty: term(r, ctx, 4), val: term(r, ctx, 6) }
                }
            })
            .collect()
    }

    /// The binders `close_*` put around an application body.
    fn binders(t: &Tm) -> usize {
        match &**t {
            Term::Let { body, .. } | Term::Lam { body, .. } => 1 + binders(body),
            _ => 0,
        }
    }

    #[test]
    fn close_wraps_agrees_with_the_obvious_loop() {
        let mut r = Lcg(7);
        let mut cases_with_drops = 0;
        for _ in 0..400 {
            let (outer, n) = (r.next(4) as u32, r.next(12) as u32);
            let ws = wraps(&mut r, outer, n);
            // an application, so the binders of the result are the wrappers
            let body = mk::app(term(&mut r, outer + n, 12), term(&mut r, outer + n, 12));
            let (a, b) = (close_wraps(&ws, body.clone()), close_naive(&ws, body));
            assert_eq!(format!("{a:?}"), format!("{b:?}"));
            if binders(&a) < ws.len() {
                cases_with_drops += 1;
            }
        }
        assert!(cases_with_drops > 50, "the cases drop lets ({cases_with_drops})");
        // a used let is kept, an unused one is dropped and the variables
        // above it renumbered: `h0 x` (`x` the enclosing variable) under
        // `let h0; let h1` closes to `let h0; h0 x`
        let ws = vec![
            Wrap::Let { name: mk::name("h0"), ty: mk::ty(), val: mk::ty() },
            Wrap::Let { name: mk::name("h1"), ty: mk::ty(), val: mk::ty() },
        ];
        let a = close_wraps(&ws, mk::app(mk::var(1), mk::var(2)));
        assert_eq!(format!("{a:?}"), format!("{:?}", mk::let_("h0", Rel::Irr, mk::ty(), mk::ty(), mk::app(mk::var(0), mk::var(1)))));
        // and a let used only by a kept let's value is kept
        let ws = vec![
            Wrap::Let { name: mk::name("h0"), ty: mk::ty(), val: mk::ty() },
            Wrap::Let { name: mk::name("h1"), ty: mk::ty(), val: mk::var(0) },
        ];
        let a = close_wraps(&ws, mk::var(0));
        assert_eq!(binders(&a), 2);
    }

    /// A balanced application tree of `2^d` leaves over the enclosing
    /// variables `base ..= base + 2`.
    fn tree(d: u32, base: u32, k: &mut u32) -> Tm {
        if d == 0 {
            *k += 1;
            return if (*k).is_multiple_of(2) { mk::ty() } else { mk::var(base + *k % 3) };
        }
        mk::app(tree(d - 1, base, k), tree(d - 1, base, k))
    }

    #[test]
    fn close_wraps_is_linear() {
        // 300 lets, none used, around a body of ~65k nodes: the obvious loop
        // visits the body twice per let (~39M nodes), this pass about twice
        let ws: Vec<Wrap> = (0..300).map(|_| Wrap::Let { name: mk::name("h"), ty: mk::ty(), val: mk::ty() }).collect();
        let body = tree(15, 300, &mut 0);
        let b0 = Budget { steps: u64::MAX / 4 };
        let _s = crate::auto::meter::Scope::enter(None, &b0);
        let mut b = Budget { steps: b0.steps };
        let out = close_wraps(&ws, body);
        crate::auto::meter::settle(&mut b);
        let used = b0.steps - b.steps;
        assert!(used < 400_000, "closing 300 unused lets around 65k nodes charged {used} units");
        // the enclosing variables moved down by the 300 dropped lets
        assert_eq!(binders(&out), 0);
        assert!(!format!("{out:?}").contains("Idx(3"), "a variable was not renumbered");
    }
}
