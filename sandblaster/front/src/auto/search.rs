//! The search driver (DESIGN.md §8.1): goal connectives, the atomic loop
//! (close → simplify → contradiction → congruence → rules → `BvRefl` →
//! case splits), promotion of irrelevant proofs, and the kernel-call
//! plumbing shared by the other `auto` modules.
//!
//! Every function works on a [`St`] (one branch) and values in its context;
//! proof terms are built at the state's current depth. A transformation of
//! the target (rewriting, unfolding) is recorded as a [`Cont`]inuation that
//! turns a proof of the new target into a proof of the old one.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry, Env, KernelError, KernelErrorKind};
use sandblaster_kernel::term::{GlobalId, Lvl, Rel, Sort, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Budget, Closure, EnvEntry, EvalError, Head, Neutral, V, Value};

use super::AutoConfig;
use super::lemmas::LemmaDb;
use super::names::Names;
use super::state::{Origin, St};
use super::util::*;
use crate::prover::{AutoFailure, Goal, Hint};

/// A hard stop of the whole search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// The kernel budget or the node limit ran out.
    Budget,
}

/// Search result: `Err(Stop)` aborts everything; `Ok(None)` is a local
/// failure (try something else).
pub type R<T> = Result<T, Stop>;

/// A recorded target transformation: from `p : motive[lhs]` build
/// `transport(ty, lhs, rhs, eq, motive, p) : motive[rhs]`. All terms were
/// built at `depth` (`motive` at `depth + 1`).
#[derive(Clone, Debug)]
pub struct Cont {
    pub depth: u32,
    pub ty: Tm,
    pub lhs: Tm,
    pub rhs: Tm,
    pub eq: Tm,
    pub motive: Tm,
    /// Irrelevant arguments applied to the transport (terms at `depth`;
    /// the motive's equation binder receives `refl`).
    pub pre: Vec<Tm>,
}

/// At most this many equations and terms in an equality closure.
const EQ_CLOSURE_MAX: usize = 48;

impl Cont {
    /// Apply to a proof at depth `d ≥ self.depth`.
    pub fn apply(&self, d: u32, p: Tm) -> Tm {
        let k = (d - self.depth) as i64;
        let mut t: Tm = Rc::new(Term::Transport {
            ty: shift(&self.ty, k),
            lhs: shift(&self.lhs, k),
            rhs: shift(&self.rhs, k),
            eq: shift(&self.eq, k),
            motive: shift_from(&self.motive, k, 1),
            val: p,
        });
        for a in &self.pre {
            t = Rc::new(Term::App { rel: Rel::Irr, fun: t, arg: shift(a, k) });
        }
        t
    }
}

/// Apply continuations (innermost last recorded) to a proof at depth `d`.
pub fn apply_conts(conts: &[Cont], d: u32, mut p: Tm) -> Tm {
    for c in conts.iter().rev() {
        p = c.apply(d, p);
    }
    p
}

/// The search engine for one goal.
pub struct Engine<'a> {
    pub env: &'a Env,
    pub b: &'a mut Budget,
    pub n: Names,
    pub cfg: &'a AutoConfig,
    pub db: &'a LemmaDb,
    pub hints: Vec<Hint>,
    /// Depth of the goal's context (hint terms live there).
    pub goal_depth: u32,
    pub nodes: u64,
    pub tried: Vec<String>,
    pub stuck: Vec<String>,
    /// A `Witness` hint not yet consumed.
    pub witness: Option<Vec<Tm>>,
    /// Next free metavariable index ([`super::ematch`]).
    pub meta_next: u32,
    /// Nesting of rule instantiations (bounds backward chaining).
    pub rule_depth: u32,
    /// Print the search steps to stderr (`SANDBLASTER_AUTO_TRACE=1`).
    pub trace: bool,
    /// Whether the proof under construction by [`Engine::atomic`] is used
    /// relevantly (a non-promotable target such as `∃`/`∨` in a relevant
    /// position): case-split arms are then solved in relevant mode.
    pub relevant: bool,
    /// Opened linarith rules per context depth ([`super::ematch`]).
    pub lin_rule_cache: BTreeMap<u32, Rc<Vec<super::ematch::LinRule>>>,
    /// Quoted values by (value address, depth) ([`Engine::quote`]).
    quote_cache: RefCell<super::util::FxMap<(usize, u32), (V, Tm)>>,
    rec_cache: RefCell<BTreeMap<u32, bool>>,
    /// Whether a ground value holds a metavariable, by value address (the
    /// value kept alive): e-matching asks it at every binding
    /// ([`Engine::ground_has_meta`]).
    meta_memo: super::util::FxMap<usize, (V, bool)>,
    /// Inside an atom-congruence enrichment ([`super::arith`]): nested
    /// linarith calls do not start another one.
    pub in_atom_congr: bool,
    /// Inside the case split of a scrutinee determination
    /// ([`super::facts`]): the arms' saturation does not determine further
    /// scrutinees (each determination rewrites the facts of its arms, and
    /// nested ones cascade through every disjunct of a large fact).
    pub in_determination: bool,
    /// Linear arithmetic without integer cuts and disequality splits (the
    /// simplifier's deciders, [`super::rewrite`]): cheap enough to try on
    /// every guard.
    pub lin_no_cuts: bool,
    /// The simplifier's fact and target rewriting is off (a retry after a
    /// kernel rejection, [`prove_goal`]).
    pub no_simp: bool,
    /// The simplifier rewrote a fact or the target in this search.
    pub simp_used: bool,
    /// The simplifier's cast normal form is off ([`prove_goal`]'s last
    /// pass), and whether it produced a step in this search.
    pub no_cast: bool,
    pub cast_used: bool,
    /// [`Engine::lin_prove`] skips the certificate search of its first
    /// `lin_skip_rounds` rounds (their linearizations are still built: they
    /// feed the enrichment). A caller that knows a goal of the same class
    /// needed that many enrichments sets it (`opt::loopsum`'s class memo);
    /// the search that remains is the same, so the proof is too whenever
    /// the earlier rounds would fail again.
    pub lin_skip_rounds: u32,
    /// The round in which the last successful [`Engine::lin_prove`] found
    /// its certificate (`u32::MAX`: by an integer cut).
    pub lin_round: Option<u32>,
    /// Inside a constructor split ([`super::congr`]): the arguments'
    /// searches do not split constructors again (a long literal list, an
    /// eta-expanded array, would be split element by element).
    pub in_ctor_split: bool,
}

impl<'a> Engine<'a> {
    pub fn new(env: &'a Env, b: &'a mut Budget, cfg: &'a AutoConfig, db: &'a LemmaDb, hints: Vec<Hint>, goal_depth: u32) -> Self {
        Engine {
            env,
            b,
            n: Names::new(env),
            cfg,
            db,
            hints,
            goal_depth,
            nodes: 0,
            tried: Vec::new(),
            stuck: Vec::new(),
            witness: None,
            meta_next: 0,
            rule_depth: 0,
            trace: std::env::var_os("SANDBLASTER_AUTO_TRACE").is_some(),
            relevant: false,
            lin_rule_cache: BTreeMap::new(),
            quote_cache: RefCell::new(super::util::FxMap::default()),
            rec_cache: RefCell::new(BTreeMap::new()),
            meta_memo: super::util::FxMap::default(),
            in_atom_congr: false,
            in_determination: false,
            lin_no_cuts: false,
            no_simp: false,
            simp_used: false,
            no_cast: false,
            cast_used: false,
            lin_skip_rounds: 0,
            lin_round: None,
            in_ctor_split: false,
        }
    }

    /// [`has_meta`] of a value, memoized by address for this engine (values
    /// are immutable; the memo keeps each one alive, so an address is never
    /// reused): e-matching asks it of every pattern node and every bound
    /// value. The walk is charged to the meter the first time only.
    pub fn ground_has_meta(&mut self, v: &V) -> bool {
        let k = Rc::as_ptr(v) as *const () as usize;
        if let Some((_, b)) = self.meta_memo.get(&k) {
            return *b;
        }
        let b = has_meta(v);
        self.meta_memo.insert(k, (v.clone(), b));
        b
    }

    // ------------------------------------------------------------------
    // Kernel plumbing.
    // ------------------------------------------------------------------

    /// `f` on `1/frac` of the remaining step budget: its exhaustion of that
    /// slice is a failure (`None`), not the end of the search; the steps it
    /// used are charged. When the whole search is out of steps or nodes
    /// (or its deadline or memory limit settled the budget to zero), the stop
    /// passes through.
    pub fn bounded<T>(&mut self, frac: u64, f: impl FnOnce(&mut Self) -> R<Option<T>>) -> R<Option<T>> {
        self.settle();
        let total = self.b.steps;
        let slice = total / frac.max(1);
        self.b.steps = slice;
        // the node limit likewise: `1/frac` of the nodes left
        let nodes0 = self.nodes;
        let node_slice = self.cfg.max_nodes.saturating_sub(nodes0) / frac.max(1);
        self.nodes = self.cfg.max_nodes.saturating_sub(node_slice);
        let r = f(self);
        self.settle();
        let used = slice.saturating_sub(self.b.steps);
        self.b.steps = total.saturating_sub(used);
        let used_nodes = self.nodes.saturating_sub(self.cfg.max_nodes.saturating_sub(node_slice));
        self.nodes = nodes0 + used_nodes;
        match r {
            Err(Stop::Budget) if self.b.steps > 0 && self.nodes <= self.cfg.max_nodes => Ok(None),
            r => r,
        }
    }

    /// Count a search node; settle the front-end work charged since the
    /// last node ([`super::meter`]); stop when the node limit, the budget,
    /// the deadline or the memory limit is exhausted.
    pub fn tick(&mut self) -> R<()> {
        self.nodes += 1;
        let _ = super::meter::spend(1);
        if !super::meter::settle(self.b) || self.nodes > self.cfg.max_nodes {
            return Err(Stop::Budget);
        }
        Ok(())
    }

    /// Settle the pending front-end charges before a kernel call (so the
    /// kernel sees the remaining budget, zero once exhausted).
    #[inline]
    pub fn settle(&mut self) {
        super::meter::settle(self.b);
    }

    /// Map an evaluation error: exhaustion of the caller's budget stops the
    /// search, anything else is a local failure.
    pub fn ev_err<T>(&self, r: Result<T, EvalError>) -> R<Option<T>> {
        match r {
            Ok(v) => Ok(Some(v)),
            Err(_) if self.b.steps == 0 => Err(Stop::Budget),
            Err(_) => Ok(None),
        }
    }

    pub fn k_err<T>(&self, r: Result<T, KernelError>) -> R<Option<T>> {
        match r {
            Ok(v) => Ok(Some(v)),
            Err(e) if matches!(e.kind, KernelErrorKind::Eval(EvalError::OutOfFuel)) && self.b.steps == 0 => Err(Stop::Budget),
            Err(_) => Ok(None),
        }
    }

    pub fn conv(&mut self, depth: u32, a: &V, b: &V) -> R<bool> {
        if Rc::ptr_eq(a, b) {
            return Ok(true);
        }
        self.settle();
        let r = self.env.conv(Lvl(depth), a, b, self.b);
        Ok(self.ev_err(r)?.unwrap_or(false))
    }

    pub fn eval(&mut self, st: &St, t: &Tm) -> R<Option<V>> {
        self.settle();
        let r = st.eval(self.env, t, self.b);
        self.ev_err(r)
    }

    /// The environment entry binding `tm` (a term at the state's depth) to a
    /// binder of type `ty` (a `Π` domain, a `Σ` first component): a proof
    /// (`ty` a proposition) is bound as its *term*, an irrelevant closure —
    /// its value would be `refl(c)` (the evaluator's canonical proof), which
    /// reads back as `refl(Bool, c)` where the binder's `Eq(Bool, c, true)`
    /// is needed, and the kernel rejects every term quoted from it (§15 S5:
    /// "refl given as a proof of `c == true`").
    pub fn entry_for(&mut self, st: &St, ty: &V, tm: &Tm) -> R<Option<EnvEntry>> {
        if self.is_prop(ty, st.depth()) {
            return Ok(Some(irr_entry(&st.venv, tm)));
        }
        Ok(self.eval(st, tm)?.map(EnvEntry::Rel))
    }

    pub fn inst(&mut self, c: &Closure, es: Vec<EnvEntry>, depth: u32) -> R<Option<V>> {
        self.settle();
        let r = inst(self.env, c, es, depth, self.b);
        self.ev_err(r)
    }

    /// Quote a value in the state's context, memoized per value and depth:
    /// the same value at the same depth always reads back to the same term
    /// (values are immutable, and states sharing a value descend from the
    /// state that created it, so the variables it mentions have the same
    /// types). The memo keeps each value alive so its address is not reused.
    pub fn quote(&self, st: &St, v: &V) -> Tm {
        let key = (Rc::as_ptr(v) as usize, st.depth());
        if let Some((_, t)) = self.quote_cache.borrow().get(&key) {
            return t.clone();
        }
        let t = st.quote(self.env, v);
        // an unaffordable quote is a placeholder (the goal is exhausted):
        // not cached
        if !matches!(&*t, Term::Erased) {
            self.quote_cache.borrow_mut().insert(key, (v.clone(), t.clone()));
        }
        t
    }

    /// Print a value in the state's context (diagnostics).
    pub fn show(&self, st: &St, v: &V) -> String {
        if has_meta(v) {
            return "<pattern>".into();
        }
        // bounded, without quoting (failure reports on large facts)
        crate::elab::show::value(self.env, &st.names(), v, 300)
    }

    pub fn note(&mut self, s: impl Into<String>) {
        let s = s.into();
        if self.trace {
            eprintln!("[auto] {s} (heap {} MiB, steps left {})", crate::memguard::allocated() >> 20, self.b.steps);
        }
        if self.tried.len() < 64 && !self.tried.contains(&s) {
            self.tried.push(s);
        }
    }

    // ------------------------------------------------------------------
    // Classification.
    // ------------------------------------------------------------------

    /// Is `ty` a proposition (DESIGN.md §4.1: equations, `Empty`, ∧/∃ as
    /// Σ, →/∀ as Π, ∨ as `Either`, stuck predicate applications)?
    pub fn is_prop(&mut self, ty: &V, depth: u32) -> bool {
        self.is_prop_n(ty, depth, 0)
    }

    fn is_prop_n(&mut self, ty: &V, depth: u32, n: u32) -> bool {
        if n > 32 {
            return false;
        }
        match &**ty {
            Value::Eq { .. } => true,
            // `Unit` is the true proposition (the `Nil` case of
            // `ghost::seq_all`, a `None` arm of a well-formedness `match`)
            Value::Ind { ind, params } => {
                *ind == self.n.empty_ind || Some(*ind) == self.n.unit || (Some(*ind) == self.n.either && params.iter().all(|p| self.is_prop_n(p, depth, n + 1)))
            }
            Value::Pi { rel, dom, cod, .. } => {
                let x = self.env.fresh_var(Lvl(depth), *rel, dom);
                match inst(self.env, cod, vec![x], depth + 1, self.b) {
                    Ok(c) => self.is_prop_n(&c, depth + 1, n + 1),
                    Err(_) => false,
                }
            }
            Value::Sigma { snd_rel, fst, snd, .. } => {
                if *snd_rel == Rel::Irr {
                    return self.is_prop_n(fst, depth, n + 1);
                }
                let x = self.env.fresh_var(Lvl(depth), Rel::Rel, fst);
                match inst(self.env, snd, vec![x], depth + 1, self.b) {
                    Ok(c) => self.is_prop_n(&c, depth + 1, n + 1),
                    Err(_) => false,
                }
            }
            Value::Neu(Neutral { head: Head::Global { def, args }, spine }) if spine.is_empty() => {
                let Some(ty) = self.env.global_type_value(*def) else { return false };
                predicate_arity(self.env, &ty, depth, self.b) == Some(args.len() as u32)
            }
            // a predicate of the crate in a restricted view: a variable
            // standing for it ([`Hint::ViewFunction`]), fully applied
            Value::Neu(Neutral { head: Head::Var(l), spine }) if !spine.is_empty() && spine.iter().all(|e| matches!(e, sandblaster_kernel::value::Elim::App(_))) => {
                let def = self.hints.iter().find_map(|h| match h {
                    Hint::ViewFunction { def, var, .. } if var.0 == l.0 => Some(*def),
                    _ => None,
                });
                let Some(ty) = def.and_then(|d| self.env.global_type_value(d)) else { return false };
                predicate_arity(self.env, &ty, depth, self.b) == Some(spine.len() as u32)
            }
            Value::Neu(Neutral { spine, .. }) => spine.iter().any(|e| matches!(e, sandblaster_kernel::value::Elim::Match { .. })),
            _ => false,
        }
    }

    /// Is a global recursive (its stored body mentions itself)?
    pub fn is_recursive(&self, g: GlobalId) -> bool {
        if let Some(r) = self.rec_cache.borrow().get(&g.0) {
            return *r;
        }
        let r = self.env.global_body(g).is_some_and(|body| mentions_global(&body, g));
        self.rec_cache.borrow_mut().insert(g.0, r);
        r
    }

    /// Does a neutral global application stand for a stuck unfoldable
    /// definition (recursive or opaque, fully applied)?
    pub fn is_unfoldable_head(&self, def: GlobalId, nargs: usize) -> bool {
        let Some(ar) = self.env.global_arity(def) else { return false };
        if nargs as u32 != ar {
            return false;
        }
        if self.env.global_kind(def) == Some(sandblaster_kernel::term::DefKind::Intrinsic) {
            return false;
        }
        self.is_recursive(def) || self.env.global_opaque(def).unwrap_or(false)
    }

    // ------------------------------------------------------------------
    // Term builders.
    // ------------------------------------------------------------------

    pub fn bool_ty(&self) -> Tm {
        mk::bool_ty(self.n.bool_ind)
    }

    pub fn refl_of(&self, st: &St, ty: &V, v: &V) -> Tm {
        mk::refl(self.quote(st, ty), st.quote_at(self.env, v, ty))
    }

    /// `eq::sym A a b e : Eq(A, b, a)` (terms at the same depth). Without
    /// the prelude lemma, a transport.
    pub fn sym(&self, a_ty: &Tm, a: &Tm, b: &Tm, e: &Tm) -> Tm {
        match self.n.eq_sym {
            Some(g) => apps(mk::global(g), [(Rel::Rel, a_ty.clone()), (Rel::Rel, a.clone()), (Rel::Rel, b.clone()), (Rel::Rel, e.clone())]),
            None => Rc::new(Term::Transport {
                ty: a_ty.clone(),
                lhs: a.clone(),
                rhs: b.clone(),
                eq: e.clone(),
                motive: mk::eq(shift(a_ty, 1), mk::var(0), shift(a, 1)),
                val: mk::refl(a_ty.clone(), a.clone()),
            }),
        }
    }

    /// Equality closure: a target `a == b` (of any type) whose sides are
    /// joined by a chain of fact equations over the same type — each used in
    /// either direction, sides compared by conversion — is proven by
    /// `eq::sym`/`eq::trans` along the chain (breadth first from `a`, at most
    /// [`EQ_CLOSURE_MAX`] terms). The kernel checks the chain; equations of
    /// integers are left to `linarith`, which also handles them, so this
    /// matters for sequences, results, structures and tuples.
    pub fn eq_closure(&mut self, st: &St, t: &V) -> R<Option<Tm>> {
        let Some((aty, l, r)) = as_eq(t) else { return Ok(None) };
        let (aty, l, r) = (aty.clone(), l.clone(), r.clone());
        let d = st.depth();
        let mut eqs: Vec<(V, V, Tm)> = Vec::new();
        for f in st.scan_facts() {
            let Some((fty, x, y)) = as_eq(&f.ty) else { continue };
            if !self.conv(d, fty, &aty)? {
                continue;
            }
            eqs.push((x.clone(), y.clone(), st.var(f.lvl)));
        }
        if eqs.is_empty() || eqs.len() > EQ_CLOSURE_MAX {
            return Ok(None);
        }
        let a_tm = self.quote(st, &aty);
        let l_tm = st.quote_at(self.env, &l, &aty);
        let mut seen: Vec<(V, Tm)> = vec![(l.clone(), mk::refl(a_tm.clone(), l_tm.clone()))];
        let mut i = 0;
        while i < seen.len() && seen.len() <= EQ_CLOSURE_MAX {
            let (n, pn) = seen[i].clone();
            if i > 0 && self.conv(d, &n, &r)? {
                return Ok(Some(self.promote(st, t, pn)));
            }
            for (x, y, e) in eqs.clone() {
                for fwd in [true, false] {
                    let (from, to) = if fwd { (&x, &y) } else { (&y, &x) };
                    if !self.conv(d, &n, from)? {
                        continue;
                    }
                    let mut known = false;
                    for (v, _) in &seen {
                        if self.conv(d, v, to)? {
                            known = true;
                            break;
                        }
                    }
                    if known {
                        continue;
                    }
                    let (x_tm, y_tm) = (st.quote_at(self.env, &x, &aty), st.quote_at(self.env, &y, &aty));
                    // `e : Eq(A, x, y)`, and `n` is `from` by conversion
                    let step = if fwd { e.clone() } else { self.sym(&a_tm, &x_tm, &y_tm, &e) };
                    let n_tm = st.quote_at(self.env, &n, &aty);
                    let to_tm = if fwd { y_tm } else { x_tm };
                    let p = self.trans(&a_tm, &l_tm, &n_tm, &to_tm, &pn, &step);
                    seen.push((to.clone(), p));
                }
            }
            i += 1;
        }
        Ok(None)
    }

    /// `eq::trans A a b c e1 e2 : Eq(A, a, c)`.
    pub fn trans(&self, a_ty: &Tm, a: &Tm, b: &Tm, c: &Tm, e1: &Tm, e2: &Tm) -> Tm {
        match self.n.eq_trans {
            Some(g) => apps(
                mk::global(g),
                [
                    (Rel::Rel, a_ty.clone()),
                    (Rel::Rel, a.clone()),
                    (Rel::Rel, b.clone()),
                    (Rel::Rel, c.clone()),
                    (Rel::Rel, e1.clone()),
                    (Rel::Rel, e2.clone()),
                ],
            ),
            None => Rc::new(Term::Transport {
                ty: a_ty.clone(),
                lhs: b.clone(),
                rhs: c.clone(),
                eq: e2.clone(),
                motive: mk::eq(shift(a_ty, 1), shift(a, 1), mk::var(0)),
                val: e1.clone(),
            }),
        }
    }

    /// `Empty` from a proof of `Eq(Bool, false, true)`.
    pub fn false_ne_true(&self, p: Tm) -> Tm {
        match self.n.false_ne_true {
            Some(g) => mk::app(mk::global(g), p),
            None => {
                // transport(Bool, false, true, p, y. match y return Type with
                // | false => Eq(Bool, true, true) | true => Empty end, refl)
                let bi = self.n.bool_ind;
                let motive = Rc::new(Term::Match {
                    ind: bi,
                    params: vec![],
                    scrut: mk::var(0),
                    motive: mk::ty(),
                    arms: vec![
                        mk::arm(&[], mk::eq_bool(bi, mk::bool_lit(bi, true), true)),
                        mk::arm(&[], mk::ind(self.n.empty_ind, vec![])),
                    ],
                });
                Rc::new(Term::Transport {
                    ty: mk::bool_ty(bi),
                    lhs: mk::bool_lit(bi, false),
                    rhs: mk::bool_lit(bi, true),
                    eq: p,
                    motive,
                    val: mk::refl(mk::bool_ty(bi), mk::bool_lit(bi, true)),
                })
            }
        }
    }

    /// `Empty` from `p1 : Eq(Bool, c, true)` and `p2 : Eq(Bool, c, false)`.
    pub fn bool_clash(&self, c: &Tm, p1: &Tm, p2: &Tm) -> Tm {
        let bt = self.bool_ty();
        let (tt, ff) = (mk::bool_lit(self.n.bool_ind, true), mk::bool_lit(self.n.bool_ind, false));
        // false = c (sym p2), c = true (p1)
        let s = self.sym(&bt, c, &ff, p2);
        let e = self.trans(&bt, &ff, c, &tt, &s, p1);
        self.false_ne_true(e)
    }

    /// Promote an irrelevant proof of an atomic target so it is usable in
    /// relevant positions (§5.3).
    pub fn promote(&self, st: &St, t: &V, p: Tm) -> Tm {
        if matches!(&*p, Term::Refl { .. }) {
            return p;
        }
        match &**t {
            Value::Eq { ty, lhs, rhs } => match self.n.eq_promote {
                Some(g) => apps(
                    mk::global(g),
                    [
                        (Rel::Rel, self.quote(st, ty)),
                        (Rel::Rel, st.quote_at(self.env, lhs, ty)),
                        (Rel::Rel, st.quote_at(self.env, rhs, ty)),
                        (Rel::Irr, p),
                    ],
                ),
                None => p,
            },
            Value::Ind { ind, .. } if *ind == self.n.empty_ind => Rc::new(Term::Absurd { ty: mk::ind(self.n.empty_ind, vec![]), proof: p }),
            _ => p,
        }
    }

    /// `absurd(t, p)` for `p : Empty`.
    pub fn absurd(&self, st: &St, t: &V, p: Tm) -> Tm {
        Rc::new(Term::Absurd { ty: self.quote(st, t), proof: p })
    }

    // ------------------------------------------------------------------
    // Goal connectives (§8.1 step 3).
    // ------------------------------------------------------------------

    /// Prove `t` in a new frame of `st` (the result is closed at `st`'s
    /// depth). `irr`: the result is only used irrelevantly (no promotion).
    pub fn solve(&mut self, st: &St, t: V, irr: bool) -> R<Option<Tm>> {
        let mut c = st.child();
        let body = self.solve_in(&mut c, t, irr)?;
        Ok(body.map(|b| c.finish(b)))
    }

    pub fn solve_in(&mut self, st: &mut St, t: V, irr: bool) -> R<Option<Tm>> {
        self.tick()?;
        let d = st.depth();
        match &*t {
            Value::Pi { name, rel, dom, cod } => {
                let is_prop = self.is_prop(dom, d);
                let e = st.push_lam(self.env, name.clone(), *rel, dom.clone(), is_prop);
                let Some(cod_v) = self.inst(cod, vec![e], st.depth())? else { return Ok(None) };
                self.solve_in(st, cod_v, irr)
            }
            Value::Sigma { snd_rel, fst, snd, .. } if self.is_prop(&t, d) => {
                if self.is_prop(fst, d) {
                    self.solve_and(st, &t, fst, snd, *snd_rel, irr)
                } else {
                    self.solve_exists(st, &t, irr)
                }
            }
            Value::Ind { ind, .. } if Some(*ind) == self.n.unit => Ok(Some(mk::ctor(*ind, 0, vec![], vec![]))),
            Value::Ind { ind, params } if Some(*ind) == self.n.either && params.len() == 2 && self.is_prop(&t, d) => {
                let (p, q) = (params[0].clone(), params[1].clone());
                let ind = *ind;
                // each side without case splits first: when the side to
                // prove depends on a case (`first || x > 0` from `g != 0 ||
                // first`), the split belongs around the disjunction (below),
                // and a side's own splits would only use up the budget
                let splits = st.depth_left;
                let mut flat = st.clone();
                flat.depth_left = 0;
                // each side cheaply first (no integer cuts either): a false
                // side costs little before the true one is tried
                let saved = std::mem::replace(&mut self.lin_no_cuts, true);
                self.note("∨: left (cheap)");
                let cheap_l = self.solve(&flat, p.clone(), irr);
                let cheap_r = match &cheap_l {
                    Ok(None) => {
                        self.note("∨: right (cheap)");
                        Some(self.solve(&flat, q.clone(), irr))
                    }
                    _ => None,
                };
                self.lin_no_cuts = saved;
                if let Some(pl) = cheap_l? {
                    return Ok(Some(mk::ctor(ind, 0, vec![self.quote(st, &p), self.quote(st, &q)], vec![pl])));
                }
                if let Some(pr) = cheap_r.transpose()?.flatten() {
                    return Ok(Some(mk::ctor(ind, 1, vec![self.quote(st, &p), self.quote(st, &q)], vec![pr])));
                }
                // a side that is a boolean test (`a != b || c != d`, `x <= 3 ||
                // f(x) == 7`): split on that test; one arm is that side, the
                // other has its negation as a fact for the other side
                if splits > 0
                    && let Some(pf) = self.disjunct_split(st, &t, &p, &q, splits)?
                {
                    return Ok(Some(pf));
                }
                self.note("∨: left");
                if let Some(pl) = self.solve(&flat, p.clone(), irr)? {
                    return Ok(Some(mk::ctor(ind, 0, vec![self.quote(st, &p), self.quote(st, &q)], vec![pl])));
                }
                self.note("∨: right");
                if let Some(pr) = self.solve(&flat, q.clone(), irr)? {
                    return Ok(Some(mk::ctor(ind, 1, vec![self.quote(st, &p), self.quote(st, &q)], vec![pr])));
                }
                if splits == 0 {
                    return self.atomic_in(st, t.clone(), irr);
                }
                // Contradictory facts or case analysis may still prove it.
                if let Some(pf) = self.atomic_in(st, t.clone(), irr)? {
                    return Ok(Some(pf));
                }
                // (then each side with its own case splits)
                if let Some(pl) = self.solve(st, p.clone(), irr)? {
                    return Ok(Some(mk::ctor(ind, 0, vec![self.quote(st, &p), self.quote(st, &q)], vec![pl])));
                }
                if let Some(pr) = self.solve(st, q.clone(), irr)? {
                    return Ok(Some(mk::ctor(ind, 1, vec![self.quote(st, &p), self.quote(st, &q)], vec![pr])));
                }
                Ok(None)
            }
            Value::Neu(Neutral { head: Head::Global { def, args }, spine }) if spine.is_empty() && self.is_prop(&t, d) => {
                let def = *def;
                let n = args.len();
                // a fact that is the predicate itself, before unfolding it
                // (a relevant use needs a relevant fact: a proof of a
                // predicate cannot be promoted like an equation's)
                if let Some(p) = self.fact_exact(st, &t, irr)? {
                    return Ok(Some(p));
                }
                if let Some(p) = self.solve_unfold(st, &t, def, n, irr)? {
                    return Ok(Some(p));
                }
                self.atomic_in(st, t.clone(), irr)
            }
            _ => {
                // Built irrelevantly, then promoted (equations, `Empty`).
                // Also when the result is only used irrelevantly, if binders
                // were introduced since the goal context: the proof uses
                // them (path equations, derived facts, pairs) freely, which
                // the kernel allows only in an irrelevant position entered
                // after they are bound (phase-4 resurrection rule) — the
                // promotion is that position.
                let p = self.atomic_in(st, t.clone(), true)?;
                Ok(p.map(|p| if irr && st.depth() == self.goal_depth { p } else { self.promote(st, &t, p) }))
            }
        }
    }

    /// `p ∨ q` by a case split on the boolean test of a side (`Eq(Bool, c,
    /// b)` with `c` stuck), not yet split on in this branch: in the arm
    /// where `c` is `b` that side holds by the path equation; in the other,
    /// the other side is proven with `c` decided.
    fn disjunct_split(&mut self, st: &mut St, t: &V, p: &V, q: &V, splits: u32) -> R<Option<Tm>> {
        let bi = self.n.bool_ind;
        for side in [p, q] {
            let Some(c) = self.side_test(st, side)? else { continue };
            // not a test split on in this branch already, nor one a fact
            // decides (then one arm is a contradiction: nothing to gain)
            let mut seen = false;
            for u in &st.split_vals {
                if self.conv(st.depth(), u, &c)? {
                    seen = true;
                    break;
                }
            }
            for f in st.facts.iter().rev().take(256) {
                if seen {
                    break;
                }
                if let Some((_, l, r)) = as_eq(&f.ty)
                    && bool_lit(bi, r).is_some()
                    && self.conv(st.depth(), l, &c)?
                {
                    seen = true;
                }
            }
            if seen {
                continue;
            }
            self.note("∨: split on a side's test");
            // on a slice of the remaining budget: a split that does not close
            // leaves the rest to the search below
            return self.bounded(8, |e| e.case_split(st, &c, bi, &[], t, true, splits.saturating_sub(1)));
        }
        Ok(None)
    }

    /// The boolean test a disjunct states: `c` for `Eq(Bool, c, b)` (`c`
    /// stuck), `a == b` (the machine or integer comparison) for an integer
    /// equation `Eq(Int, a, b)` or its negation `Eq(Int, a, b) -> Empty`
    /// (`requires(a != b || ..)`).
    fn side_test(&mut self, st: &St, side: &V) -> R<Option<V>> {
        let bi = self.n.bool_ind;
        let d = st.depth();
        let int_eq = |this: &mut Self, w: Width, l: &V, r: &V| -> R<Option<V>> {
            let it = Rc::new(Value::IntTy(w));
            let (lt, rt) = (st.quote_at(this.env, l, &it), st.quote_at(this.env, r, &it));
            let c = sandblaster_kernel::prim::prim0(sandblaster_kernel::term::PrimOp::Eq(w), vec![lt, rt]);
            let v = this.eval(st, &c)?;
            Ok(v.filter(|v| as_neu(v).is_some()))
        };
        match &**side {
            Value::Eq { ty, lhs, rhs } if matches!(&**ty, Value::Ind { ind, .. } if *ind == bi) => Ok((bool_lit(bi, rhs).is_some() && as_neu(lhs).is_some()).then(|| lhs.clone())),
            Value::Eq { ty, lhs, rhs } => match &**ty {
                Value::IntTy(w) => int_eq(self, *w, lhs, rhs),
                _ => Ok(None),
            },
            Value::Pi { rel, dom, cod, .. } => {
                let Value::Eq { ty, lhs, rhs } = &**dom else { return Ok(None) };
                let Value::IntTy(w) = &**ty else { return Ok(None) };
                let x = self.env.fresh_var(Lvl(d), *rel, dom);
                let Some(cv) = self.inst(cod, vec![x], d + 1)? else { return Ok(None) };
                if !matches!(&*cv, Value::Ind { ind, .. } if *ind == self.n.empty_ind) {
                    return Ok(None);
                }
                int_eq(self, *w, lhs, rhs)
            }
            _ => Ok(None),
        }
    }

    /// A fact whose statement is `t` (by conversion) and that may be used
    /// here: any fact for an irrelevant use, a relevant context entry for a
    /// relevant one.
    fn fact_exact(&mut self, st: &St, t: &V, irr: bool) -> R<Option<Tm>> {
        for f in st.facts.iter().rev() {
            let rel_ok = irr || st.ctx.entries.get(f.lvl as usize).is_some_and(|e| e.rel == Rel::Rel);
            if rel_ok && self.conv(st.depth(), &f.ty, t)? {
                return Ok(Some(st.var(f.lvl)));
            }
        }
        Ok(None)
    }

    /// Dependent conjunction `Σ(h : P). Q`: prove `P`, then `Q[h := p]` with
    /// `P` as a fact.
    fn solve_and(&mut self, st: &mut St, t: &V, fst: &V, snd: &Closure, snd_rel: Rel, irr: bool) -> R<Option<Tm>> {
        self.note("∧: split");
        let Some(p1) = self.solve(st, fst.clone(), irr)? else { return Ok(None) };
        // The second conjunct depends on the first only through proofs
        // (irrelevant positions): instantiate it with the let-bound fact
        // (quoting it gives the fact variable, never a stuck proof value).
        let mut c = st.child();
        let lvl = c.push_fact(self.env, fst.clone(), p1.clone(), Origin::Derived("conjunct"));
        let Some(q) = self.inst(snd, vec![EnvEntry::Rel(neu_var(lvl))], c.depth())? else { return Ok(None) };
        let Some(body) = self.solve_in(&mut c, q, irr || snd_rel == Rel::Irr)? else { return Ok(None) };
        let p2 = c.finish(body);
        Ok(Some(mk::pair(self.quote(st, t), p1, p2)))
    }

    /// `exists` targets: witnesses from a `Witness` hint or by matching the
    /// body's conjuncts against facts ([`super::ematch`]).
    fn solve_exists(&mut self, st: &mut St, t: &V, irr: bool) -> R<Option<Tm>> {
        let d = st.depth();
        let ws: Vec<V> = if let Some(ws) = self.witness.take() {
            self.note("∃: witnesses from hint");
            let k = (d - self.goal_depth) as i64;
            let mut out = Vec::new();
            for w in ws {
                let Some(v) = self.eval(st, &shift(&w, k))? else { return Ok(None) };
                out.push(v);
            }
            out
        } else {
            self.note("∃: witnesses by unification against facts");
            match self.exists_witnesses(st, t)? {
                Some(ws) => ws,
                // Saturation, contradictions or a case split may still
                // expose the witnesses (the arms retry the unification).
                None => return self.atomic_in(st, t.clone(), irr),
            }
        };
        // Build the nested pairs.
        let mut cur = t.clone();
        let mut layers: Vec<(Tm, Tm)> = Vec::new();
        for w in &ws {
            let Value::Sigma { fst, snd, .. } = &*cur.clone() else { return Ok(None) };
            let sig = self.quote(st, &cur);
            let wt = st.quote_at(self.env, w, fst);
            layers.push((sig, wt));
            let Some(next) = self.inst(snd, vec![EnvEntry::Rel(w.clone())], d)? else { return Ok(None) };
            cur = next;
        }
        let Some(mut p) = self.solve(st, cur, irr)? else { return Ok(None) };
        for (sig, wt) in layers.into_iter().rev() {
            p = mk::pair(sig, wt, p);
        }
        Ok(Some(p))
    }

    /// A stuck predicate application: prove its unfolded body.
    fn solve_unfold(&mut self, st: &mut St, t: &V, def: GlobalId, _n: usize, irr: bool) -> R<Option<Tm>> {
        if !self.cfg.mode.allows_delta(def) {
            return Ok(None);
        }
        let Some((args, body)) = self.unfold_app(st, t, def)? else { return Ok(None) };
        self.note(format!("unfold predicate {}", self.env.global_name(def).map(|s| s.to_string()).unwrap_or_default()));
        let Some(p) = self.solve(st, body, irr)? else { return Ok(None) };
        Ok(Some(Rc::new(Term::Unfold { def, args: args.into_iter().map(|(_, a)| a).collect(), to_body: false, val: p })))
    }

    /// The argument terms of a quoted global application and the value of
    /// the definition's body applied to them.
    pub fn unfold_app(&mut self, st: &St, v: &V, def: GlobalId) -> R<Option<Unfolded>> {
        let tm = self.quote(st, v);
        let mut args = Vec::new();
        let mut h = &tm;
        while let Term::App { rel, fun, arg } = &**h {
            args.push((*rel, arg.clone()));
            h = fun;
        }
        if !matches!(&**h, Term::Global(g) if *g == def) {
            return Ok(None);
        }
        args.reverse();
        let Some(body) = self.env.global_body(def) else { return Ok(None) };
        let app = apps(body, args.clone());
        let Some(bv) = self.eval(st, &app)? else { return Ok(None) };
        Ok(Some((args, bv)))
    }

    // ------------------------------------------------------------------
    // The atomic loop.
    // ------------------------------------------------------------------

    /// Prove an atomic target; the proof is only valid irrelevantly.
    /// [`Engine::atomic`] with the relevance of its use (`irr`).
    pub fn atomic_in(&mut self, st: &mut St, t: V, irr: bool) -> R<Option<Tm>> {
        let saved = std::mem::replace(&mut self.relevant, !irr);
        let r = self.atomic(st, t);
        self.relevant = saved;
        r
    }

    pub fn atomic(&mut self, st: &mut St, t0: V) -> R<Option<Tm>> {
        if self.trace {
            eprintln!("[auto] atomic target: {}", truncate(self.show(st, &t0), 400));
        }
        // a target that is a fact already, or holds by conversion: closed
        // before the simplifier and saturation (in a large context the
        // saturation of the facts can use up the goal's budget before
        // `close` sees the fact: a conjunct of a law's claim, a callee's
        // `requires` stated as a fact)
        if let Some(p) = self.close_by_fact(st, &t0)? {
            return Ok(Some(p));
        }
        let mut t = t0;
        let mut conts: Vec<Cont> = Vec::new();
        // the simplifier's normal form of the target first (its casts, and the
        // guards the facts decide), so the facts' normal forms meet it before
        // any search (saturation can be costly)
        if !self.no_simp
            && let Some((t2, cs)) = self.simp_target(st, &t)?
        {
            st.rewrites += cs.len() as u32;
            conts.extend(cs);
            t = t2;
            if matches!(&*t, Value::Pi { .. } | Value::Sigma { .. }) {
                let p = self.solve(st, t.clone(), !self.relevant)?;
                return Ok(p.map(|p| apply_conts(&conts, st.depth(), p)));
            }
        }
        match self.saturate_for(st, Some(&t))? {
            super::facts::Saturated::Contradiction(p) => {
                let a = self.absurd(st, &t, p);
                return Ok(Some(apply_conts(&conts, st.depth(), a)));
            }
            super::facts::Saturated::Target(lvl) => return Ok(Some(apply_conts(&conts, st.depth(), st.var(lvl)))),
            super::facts::Saturated::Done => {}
        }
        // Root-level hints (rewrite / unfold) apply once per branch.
        let hinted = if st.hints_done {
            None
        } else {
            st.hints_done = true;
            self.apply_hints(st, &t)?
        };
        if let Some((t2, cs)) = hinted {
            conts.extend(cs);
            t = t2;
            if matches!(&*t, Value::Pi { .. }) {
                let p = self.solve(st, t.clone(), !self.relevant)?;
                return Ok(p.map(|p| apply_conts(&conts, st.depth(), p)));
            }
        }
        loop {
            self.tick()?;
            if let Some(p) = self.close(st, &t)? {
                return Ok(Some(apply_conts(&conts, st.depth(), p)));
            }
            // sides joined by a chain of fact equations
            if let Some(p) = self.eq_closure(st, &t)? {
                return Ok(Some(apply_conts(&conts, st.depth(), p)));
            }
            // before rewriting or unfolding either side
            if let Some(p) = self.arg_congruence(st, &t)? {
                return Ok(Some(apply_conts(&conts, st.depth(), p)));
            }
            // a fact about the same function at arithmetically equal
            // arguments (`r(y) == 4` for the target `r(x - 1) == 4`)
            if let Some(p) = self.fact_congruence(st, &t)? {
                return Ok(Some(apply_conts(&conts, st.depth(), p)));
            }
            // constructors with `Irr` fields (invariants, §15.3)
            if let Some(p) = self.irr_ctor_congruence(st, &t)? {
                return Ok(Some(apply_conts(&conts, st.depth(), p)));
            }
            // one constructor on both sides: the arguments' equations
            if let Some(p) = self.ctor_split(st, &t)? {
                return Ok(Some(apply_conts(&conts, st.depth(), p)));
            }
            // a recursive call scrutinized by both the target and a fact
            if let Some(p) = self.shared_scrutinee_split(st, &t)? {
                return Ok(Some(apply_conts(&conts, st.depth(), p)));
            }
            let nfacts = st.facts.len();
            match self.simplify(st, &t)? {
                Some((t2, c)) => {
                    conts.extend(c);
                    t = t2;
                    if matches!(&*t, Value::Pi { .. }) {
                        // A rewrite that generalized dependent facts: the new
                        // target quantifies over their rewritten versions.
                        let p = self.solve(st, t.clone(), !self.relevant)?;
                        return Ok(p.map(|p| apply_conts(&conts, st.depth(), p)));
                    }
                    if st.facts.len() != nfacts
                        && let Some(p) = self.saturate(st)?
                    {
                        let a = self.absurd(st, &t, p);
                        return Ok(Some(apply_conts(&conts, st.depth(), a)));
                    }
                }
                None => break,
            }
        }
        if let Some(p) = self.expanded_close(st, &t)? {
            return Ok(Some(apply_conts(&conts, st.depth(), p)));
        }
        if let Some(p) = self.contradiction(st)? {
            let a = self.absurd(st, &t, p);
            return Ok(Some(apply_conts(&conts, st.depth(), a)));
        }
        if let Some(p) = self.backward(st, &t)? {
            return Ok(Some(apply_conts(&conts, st.depth(), p)));
        }
        if self.cfg.auto_bvrefl
            && let Some(p) = self.try_bvrefl(st, &t, false)?
        {
            return Ok(Some(apply_conts(&conts, st.depth(), p)));
        }
        if st.depth_left > 0
            && let Some(p) = self.splits(st, &t)?
        {
            return Ok(Some(apply_conts(&conts, st.depth(), p)));
        }
        self.note_stuck(st, &t);
        Ok(None)
    }

    /// The target with its *defined* variables replaced by their
    /// definitions, closed without a case split: a fact `t == x` (either
    /// side) between a variable `x` of the target and a stuck term `t` that
    /// does not mention it — the fields of a matched result (`take(b, n) ==
    /// a` after `field(n, b) == Some((a, r))`), a pattern's parts — makes
    /// `x` an abbreviation of `t`, and a goal about `x` (`a.len() == n`)
    /// often holds by what is known about `t` (`take`'s length). Fact
    /// rewriting orients such equations towards the variable, which keeps
    /// the facts small but hides `t`'s facts from the goal. Tried after the
    /// target's own simplification is stuck, on a child state: committed
    /// only when the expanded target closes (by a fact, conversion,
    /// linear arithmetic, rewriting or a backward rule).
    fn expanded_close(&mut self, st: &mut St, t: &V) -> R<Option<Tm>> {
        let d = st.depth();
        let keys = keys_in_target(t);
        let mut defs: Vec<(u32, V, V, V, Tm)> = Vec::new();
        for f in st.scan_facts().iter().rev() {
            if defs.len() >= 4 {
                break;
            }
            let Some((ty, l, r)) = as_eq(&f.ty) else { continue };
            for (x, def, fact_is_x_def) in [(l, r, true), (r, l, false)] {
                // a variable, or the eta-expanded list or pair of an array
                // variable (`c` of `[u8; 32]`)
                let Some(xl) = self.def_var(x) else { continue };
                if as_neu(def).is_none() || self.def_var(def).is_some() || !keys.contains(&xl) || defs.iter().any(|dd| dd.0 == xl) || st.expanded.contains(&xl) {
                    continue;
                }
                // a call (`take(b, n)`, `to_array(..)`), not a projection of
                // another variable (a slice's list `fst(snd(xs))`: its view,
                // which says nothing new)
                if !matches!(&**def, Value::Neu(Neutral { head: Head::Global { .. } | Head::Prim { .. }, .. })) {
                    continue;
                }
                // a variable without a definition of its own, not mentioned by
                // its definition
                if st.ctx.entries.get(xl as usize).is_none_or(|e| e.def.is_some()) || mentions_var(def, xl) {
                    continue;
                }
                // a small definition only (read back without the goal's
                // quote charge first: a large one is not worth a try)
                if super::meter::value_cost(self.env, &st.ctx, def, Some(ty), true, 2_001) > 2_000 {
                    continue;
                }
                let dt = st.quote_at(self.env, def, ty);
                if super::meter::term_size(&dt, 401) > 400 {
                    continue;
                }
                // `e : Eq(ty, x, def)`
                let e = if fact_is_x_def {
                    st.var(f.lvl)
                } else {
                    let (at, xt) = (self.quote(st, ty), st.quote_at(self.env, x, ty));
                    self.sym(&at, &dt, &xt, &st.var(f.lvl))
                };
                defs.push((xl, ty.clone(), x.clone(), def.clone(), e));
                break;
            }
        }
        if defs.is_empty() {
            return Ok(None);
        }
        let mut c = st.child();
        let mut cur = t.clone();
        let mut conts: Vec<Cont> = Vec::new();
        for (xl, ty, x, def, e) in defs {
            if let Some((t2, k)) = self.rewrite(&c, &cur, &ty, &x, &def, e)? {
                cur = t2;
                conts.push(k);
                c.expanded.push(xl);
            }
        }
        if conts.is_empty() {
            return Ok(None);
        }
        self.note("expand defined variables in the target");
        // a bounded attempt: a tenth of what is left of the goal's step
        // budget and node limit, so a failed attempt leaves the case splits
        // that follow their means
        self.settle();
        let (steps0, nodes0) = (self.b.steps, self.nodes);
        let node_cap = (self.cfg.max_nodes.saturating_sub(nodes0)) / 10;
        for _ in 0..8 {
            self.tick()?;
            self.settle();
            if steps0.saturating_sub(self.b.steps) > steps0 / 10 || self.nodes - nodes0 > node_cap {
                break;
            }
            if let Some(p) = self.close(&mut c, &cur)? {
                let body = apply_conts(&conts, c.depth(), p);
                return Ok(Some(c.finish(body)));
            }
            if c.rewrites >= self.cfg.max_rewrites {
                break;
            }
            match self.simplify(&mut c, &cur)? {
                Some((t2, k)) => {
                    if matches!(&*t2, Value::Pi { .. }) {
                        break;
                    }
                    conts.extend(k);
                    cur = t2;
                }
                None => break,
            }
        }
        if let Some(p) = self.backward(&mut c, &cur)? {
            let body = apply_conts(&conts, c.depth(), p);
            return Ok(Some(c.finish(body)));
        }
        let _ = d;
        Ok(None)
    }

    /// [`Engine::close`] without arithmetic: reflexivity or a fact.
    fn close_by_fact(&mut self, st: &St, t: &V) -> R<Option<Tm>> {
        let d = st.depth();
        if let Some((a, l, r)) = as_eq(t)
            && self.conv(d, l, r)?
        {
            return Ok(Some(mk::refl(self.quote(st, a), st.quote_at(self.env, l, a))));
        }
        for i in (0..st.facts.len()).rev() {
            let f = st.facts[i].clone();
            if self.conv(d, &f.ty, t)? {
                return Ok(Some(st.var(f.lvl)));
            }
        }
        Ok(None)
    }

    /// Close the target directly: `refl`, `Unit`, a fact, `BvRefl` if
    /// hinted, linarith (§8.1 steps 2, 12, 13).
    pub fn close(&mut self, st: &mut St, t: &V) -> R<Option<Tm>> {
        let d = st.depth();
        if let Some((a, l, r)) = as_eq(t) {
            let (a, l, r) = (a.clone(), l.clone(), r.clone());
            if self.conv(d, &l, &r)? {
                return Ok(Some(mk::refl(self.quote(st, &a), st.quote_at(self.env, &l, &a))));
            }
        }
        if let Value::Ind { ind, .. } = &**t
            && Some(*ind) == self.n.unit
        {
            return Ok(Some(mk::ctor(*ind, 0, vec![], vec![])));
        }
        for i in (0..st.facts.len()).rev() {
            let f = st.facts[i].clone();
            if self.conv(d, &f.ty, t)? {
                return Ok(Some(st.var(f.lvl)));
            }
        }
        if self.hints.iter().any(|h| matches!(h, Hint::Bv))
            && let Some(p) = self.try_bvrefl(st, t, true)?
        {
            return Ok(Some(p));
        }
        if self.lin_goal_form(t)
            && let Some(p) = self.lin_prove(st, t, true)?
        {
            return Ok(Some(p));
        }
        Ok(None)
    }

    /// One transformation of the target (§8.1 steps 6, 8, 10, and rewrite
    /// rules): returns the new target and its continuation.
    fn simplify(&mut self, st: &mut St, t: &V) -> R<Option<(V, Vec<Cont>)>> {
        if st.rewrites >= self.cfg.max_rewrites {
            return Ok(None);
        }
        // the simplifier: every scrutinee a fact or cheap arithmetic decides
        if let Some((t2, cs)) = self.simp_target(st, t)? {
            st.rewrites += cs.len() as u32;
            return Ok(Some((t2, cs)));
        }
        if let Some((t2, c)) = self.rewrite_with_facts(st, t)? {
            st.rewrites += 1;
            return Ok(Some((t2, vec![c])));
        }
        if let Some((t2, c)) = self.rewrite_with_var_equations(st, t)? {
            st.rewrites += 1;
            return Ok(Some((t2, vec![c])));
        }
        if let Some((t2, c)) = self.decide_scrutinee(st, t)? {
            st.rewrites += 1;
            return Ok(Some((t2, vec![c])));
        }
        if let Some((t2, c)) = self.rewrite_rules(st, t)? {
            st.rewrites += 1;
            return Ok(Some((t2, vec![c])));
        }
        if st.deltas < self.cfg.max_deltas
            && let Some((t2, c)) = self.delta_step(st, t, None)?
        {
            st.deltas += 1;
            st.rewrites += 1;
            return Ok(Some((t2, vec![c])));
        }
        if let Some((t2, c)) = self.congruence_step(st, t)? {
            st.rewrites += 1;
            return Ok(Some((t2, vec![c])));
        }
        Ok(None)
    }

    /// Contradictions (§8.1 step 5) beyond saturation: linarith
    /// infeasibility of the facts, disequality facts whose equation is
    /// provable, `¬P` facts whose `P` is provable.
    pub fn contradiction(&mut self, st: &mut St) -> R<Option<Tm>> {
        let empty = Rc::new(Value::Ind { ind: self.n.empty_ind, params: vec![] });
        if let Some(p) = self.lin_prove(st, &empty, true)? {
            self.note("contradiction: linarith");
            return Ok(Some(p));
        }
        let d = st.depth();
        let facts = st.scan_facts();
        for f in &facts {
            // eq(a, b) = false / ne(a, b) = true: the opposite is provable.
            if let Some((ty, l, r)) = as_eq(&f.ty)
                && matches!(&**ty, Value::Ind { ind, .. } if *ind == self.n.bool_ind)
                && let Some(b) = bool_lit(self.n.bool_ind, r)
                && let Some((op, _)) = as_prim(l)
                && cmp_width(op).is_some()
            {
                let (l, b) = (l.clone(), b);
                let opp = Rc::new(Value::Eq {
                    ty: ty.clone(),
                    lhs: l.clone(),
                    rhs: Rc::new(Value::Ctor { ind: self.n.bool_ind, ctor: (!b) as u32, params: vec![], args: vec![] }),
                });
                if let Some(p) = self.lin_prove(st, &opp, true)? {
                    self.note("contradiction: disequality fact refuted by linarith");
                    let c = self.quote(st, &l);
                    let hv = st.var(f.lvl);
                    let (pt, pf) = if b { (hv, p) } else { (p, hv) };
                    return Ok(Some(self.bool_clash(&c, &pt, &pf)));
                }
            }
            // ¬P facts: Π(x : P). Empty.
            if let Value::Pi { rel, dom, cod, .. } = &*f.ty {
                let x = self.env.fresh_var(Lvl(d), *rel, dom);
                let cod_v = self.inst(cod, vec![x], d + 1)?;
                if matches!(cod_v.as_deref(), Some(Value::Ind { ind, .. }) if *ind == self.n.empty_ind) && self.is_prop(dom, d) {
                    let mut c = st.child();
                    c.depth_left = 0;
                    if let Some(p) = self.solve(&c, dom.clone(), true)? {
                        self.note("contradiction: ¬P fact with P provable");
                        let app = Rc::new(Term::App { rel: *rel, fun: st.var(f.lvl), arg: p });
                        return Ok(Some(app));
                    }
                }
            }
        }
        Ok(None)
    }

    /// `BvRefl` for an equation over machine integers / arrays (§8.1 step
    /// 12), accepted only if the kernel accepts it.
    pub fn try_bvrefl(&mut self, st: &St, t: &V, forced: bool) -> R<Option<Tm>> {
        let Some((ty, l, r)) = as_eq(t) else { return Ok(None) };
        let wordy = matches!(&**ty, Value::IntTy(w) if *w != Width::Int) || matches!(&**ty, Value::Sigma { .. });
        if !wordy || (!forced && !(has_bit_ops(l) || has_bit_ops(r))) {
            return Ok(None);
        }
        self.note("BvRefl");
        let term = Rc::new(Term::BvRefl { ty: self.quote(st, ty), lhs: st.quote_at(self.env, l, ty), rhs: st.quote_at(self.env, r, ty) });
        self.settle();
        let r = self.env.check(&st.ctx, &term, t, self.b);
        Ok(self.k_err(r)?.map(|_| term))
    }

    fn note_stuck(&mut self, st: &St, t: &V) {
        let mut out = Vec::new();
        self.collect_stuck(t, &mut out);
        for s in out.into_iter().take(4) {
            let txt = self.show(st, &s.val);
            if self.stuck.len() < 16 && !self.stuck.contains(&txt) {
                self.stuck.push(txt);
            }
        }
    }
}

/// The argument terms of a global application and its unfolded body.
pub type Unfolded = (Vec<(Rel, Tm)>, V);

/// The variables (levels) that occur in a value (as values, or under a
/// projection: an array variable's list is `fst(c)`).
fn keys_in_target(v: &V) -> Vec<u32> {
    let mut out = Vec::new();
    walk(v, &mut |x| {
        if let Value::Neu(Neutral { head: Head::Var(l), spine }) = &**x
            && spine.iter().all(|e| matches!(e, sandblaster_kernel::value::Elim::Fst | sandblaster_kernel::value::Elim::Snd))
            && !out.contains(&l.0)
        {
            out.push(l.0);
        }
        true
    });
    out
}

impl Engine<'_> {
    /// The level of a variable standing alone: a variable, or the eta
    /// expansion of an array variable (its list, or its pair).
    pub fn def_var(&self, v: &V) -> Option<u32> {
        as_var(v).or_else(|| self.var_like(v)).or_else(|| self.eta_list_var(v).map(|l| l.0))
    }
}

/// Does the value mention the variable of level `l`?
fn mentions_var(v: &V, l: u32) -> bool {
    let mut found = false;
    walk(v, &mut |x| {
        if as_var(x) == Some(l) || matches!(&**x, Value::Neu(Neutral { head: Head::Var(h), .. }) if h.0 == l) {
            found = true;
        }
        !found
    });
    found
}

/// Does the value contain bitwise / rotation / shift primitives?
fn has_bit_ops(v: &V) -> bool {
    use sandblaster_kernel::term::PrimOp::*;
    let mut found = false;
    walk(v, &mut |x| {
        if let Some((op, _)) = as_prim(x)
            && matches!(op, And(_) | Or(_) | Xor(_) | Not(_) | Rotl(_) | Rotr(_) | WShl(_) | WShr(_) | Shl(_) | Shr(_) | SwapBytes(_))
        {
            found = true;
        }
        if let Value::Neu(Neutral { head: Head::Global { .. }, .. }) = &**x {
            found = true;
        }
        !found
    });
    found
}

/// Does `t` mention the global `g`?
fn mentions_global(t: &Tm, g: GlobalId) -> bool {
    let mut found = false;
    visit_terms(t, &mut |x| {
        if matches!(x, Term::Global(h) if *h == g) || matches!(x, Term::Delta { def, .. } | Term::Unfold { def, .. } if *def == g) {
            found = true;
        }
    });
    found
}

/// Visit the direct children of a term with the number of binders each
/// child is under.
pub fn visit_children(t: &Tm, f: &mut dyn FnMut(&Tm, u32)) {
    match &**t {
        Term::Var(_) | Term::Global(_) | Term::Sort(_) | Term::IntTy(_) | Term::Lit { .. } | Term::Erased => {}
        Term::Pi { dom, cod: body, .. } | Term::Lam { dom, body, .. } | Term::Sigma { fst: dom, snd: body, .. } => {
            f(dom, 0);
            f(body, 1);
        }
        Term::App { fun, arg, .. } => {
            f(fun, 0);
            f(arg, 0);
        }
        Term::Let { ty, val, body, .. } => {
            f(ty, 0);
            f(val, 0);
            f(body, 1);
        }
        Term::Pair { ty, fst, snd } => {
            f(ty, 0);
            f(fst, 0);
            f(snd, 0);
        }
        Term::Fst(p) | Term::Snd(p) => f(p, 0),
        Term::Eq { ty, lhs, rhs } | Term::BvRefl { ty, lhs, rhs } => {
            f(ty, 0);
            f(lhs, 0);
            f(rhs, 0);
        }
        Term::Refl { ty, val } => {
            f(ty, 0);
            f(val, 0);
        }
        Term::Transport { ty, lhs, rhs, eq, motive, val } => {
            f(ty, 0);
            f(lhs, 0);
            f(rhs, 0);
            f(eq, 0);
            f(motive, 1);
            f(val, 0);
        }
        Term::Ind { params, .. } => params.iter().for_each(|p| f(p, 0)),
        Term::Ctor { params, args, .. } => params.iter().chain(args).for_each(|p| f(p, 0)),
        Term::Match { params, scrut, motive, arms, .. } => {
            params.iter().for_each(|p| f(p, 0));
            f(scrut, 0);
            f(motive, 1);
            arms.iter().for_each(|a| f(&a.body, a.names.len() as u32));
        }
        Term::Prim { args, proofs, .. } => args.iter().chain(proofs).for_each(|p| f(p, 0)),
        Term::Rec { args, proof } => {
            args.iter().for_each(|p| f(p, 0));
            if let Some(p) = proof {
                f(p, 0);
            }
        }
        Term::Delta { args, .. } | Term::Axiom { args, .. } => args.iter().for_each(|p| f(p, 0)),
        Term::Unfold { args, val, .. } => {
            args.iter().for_each(|p| f(p, 0));
            f(val, 0);
        }
        Term::Linarith { hyps, goal, .. } => {
            for (p, s) in hyps {
                f(p, 0);
                f(s, 0);
            }
            f(goal, 0);
        }
        Term::Absurd { ty, proof } => {
            f(ty, 0);
            f(proof, 0);
        }
    }
}

/// Visit every subterm of a term.
pub fn visit_terms(t: &Tm, f: &mut dyn FnMut(&Term)) {
    f(t);
    match &**t {
        Term::Var(_) | Term::Global(_) | Term::Sort(_) | Term::IntTy(_) | Term::Lit { .. } | Term::Erased => {}
        Term::Pi { dom, cod: body, .. } | Term::Lam { dom, body, .. } | Term::Sigma { fst: dom, snd: body, .. } => {
            visit_terms(dom, f);
            visit_terms(body, f);
        }
        Term::App { fun, arg, .. } => {
            visit_terms(fun, f);
            visit_terms(arg, f);
        }
        Term::Let { ty, val, body, .. } => {
            visit_terms(ty, f);
            visit_terms(val, f);
            visit_terms(body, f);
        }
        Term::Pair { ty, fst, snd } => {
            visit_terms(ty, f);
            visit_terms(fst, f);
            visit_terms(snd, f);
        }
        Term::Fst(p) | Term::Snd(p) => visit_terms(p, f),
        Term::Eq { ty, lhs, rhs } | Term::BvRefl { ty, lhs, rhs } => {
            visit_terms(ty, f);
            visit_terms(lhs, f);
            visit_terms(rhs, f);
        }
        Term::Refl { ty, val } => {
            visit_terms(ty, f);
            visit_terms(val, f);
        }
        Term::Transport { ty, lhs, rhs, eq, motive, val } => {
            for x in [ty, lhs, rhs, eq, motive, val] {
                visit_terms(x, f);
            }
        }
        Term::Ind { params, .. } => params.iter().for_each(|p| visit_terms(p, f)),
        Term::Ctor { params, args, .. } => params.iter().chain(args).for_each(|p| visit_terms(p, f)),
        Term::Match { params, scrut, motive, arms, .. } => {
            params.iter().for_each(|p| visit_terms(p, f));
            visit_terms(scrut, f);
            visit_terms(motive, f);
            arms.iter().for_each(|a| visit_terms(&a.body, f));
        }
        Term::Prim { args, proofs, .. } => args.iter().chain(proofs).for_each(|p| visit_terms(p, f)),
        Term::Rec { args, proof } => {
            args.iter().for_each(|p| visit_terms(p, f));
            if let Some(p) = proof {
                visit_terms(p, f);
            }
        }
        Term::Delta { args, .. } | Term::Axiom { args, .. } => args.iter().for_each(|p| visit_terms(p, f)),
        Term::Unfold { args, val, .. } => {
            args.iter().for_each(|p| visit_terms(p, f));
            visit_terms(val, f);
        }
        Term::Linarith { hyps, goal, .. } => {
            for (p, s) in hyps {
                visit_terms(p, f);
                visit_terms(s, f);
            }
            visit_terms(goal, f);
        }
        Term::Absurd { ty, proof } => {
            visit_terms(ty, f);
            visit_terms(proof, f);
        }
    }
}

pub fn truncate(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut cut = max;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &s[..cut])
}

/// A context extended with one relevant variable `y : ty` (for motives).
pub fn ctx_with(ctx: &Ctx, ty: &V) -> Ctx {
    ctx.push(CtxEntry { name: Rc::from("y"), rel: Rel::Rel, ty: ty.clone(), def: None })
}

/// Is `v` the sort `Type`?
pub fn is_type_sort(v: &V) -> bool {
    matches!(&**v, Value::Sort(Sort::Type))
}

/// Entry point: prove a goal. The plain search runs first; when it fails
/// (no proof, an exhausted step budget, or a proof the kernel rejects), the
/// search runs once more with the simplifier's fact and target rewriting
/// (`rewrite::simp_fact`, `simp_target`), on a fresh step budget and the
/// rest of the goal's deadline; a small target ([`SIMP_FIRST_MAX_NODES`])
/// goes the other way round. Either order retries with the other, so the
/// simplifier never loses a goal the plain search proves
/// (`SANDBLASTER_SIMP=first` tries it first always, `off` never).
pub fn prove_goal(env: &Env, g: &Goal, b: &mut Budget, cfg: &AutoConfig, db: &LemmaDb) -> Result<Tm, AutoFailure> {
    let mode = simp_mode();
    if mode == SimpMode::Off {
        return prove_goal_with(env, g, b, cfg, db, Pass::Plain).map_err(|(f, _)| f);
    }
    // small goals run with the simplifier first (its normal form closes
    // them directly), larger ones fall back to it after the plain search
    let first_plain = match mode {
        SimpMode::Fallback => {
            let max = simp_first_max();
            max == 0 || super::meter::value_cost(env, &g.ctx, &g.target, None, false, max + 1) > max
        }
        _ => false,
    };
    let steps0 = b.steps;
    let first = if first_plain { Pass::Plain } else { Pass::Simp };
    let (mut f, mut used) = match prove_goal_with(env, g, b, cfg, db, first) {
        Ok(t) => return Ok(t),
        Err(e) => e,
    };
    let mut label = if first_plain { "plain search" } else { "simplifier" };
    // the passes after the first: the other of plain and simplifier, then
    // the simplifier without its cast normal form when that form was used
    // (a target whose casts it could only partly rewrite can leave the
    // facts and the target in two different forms)
    let rest: &[Pass] = if first_plain { &[Pass::Simp, Pass::SimpNoCast] } else { &[Pass::Plain, Pass::SimpNoCast] };
    let mut prev = first;
    for &pass in rest {
        let worth = match (prev, pass) {
            // after the plain search, the simplifier unless the deadline or
            // memory stopped it
            (Pass::Plain, _) => !matches!(super::meter::exhausted(), Some(x) if x != super::meter::Exhaustion::Steps),
            // after the simplifier, the plain search only if it ran; the
            // pass without casts only if they were rewritten
            (_, Pass::Plain) => used.simp,
            (_, Pass::SimpNoCast) => used.cast && !matches!(super::meter::exhausted(), Some(x) if x != super::meter::Exhaustion::Steps),
            _ => false,
        };
        if !worth {
            continue;
        }
        let mut b2 = Budget { steps: steps0.max(b.steps) };
        // a nested scope: its own step count, the same deadline
        let _scope = super::meter::Scope::enter(None, &b2);
        let r = prove_goal_with(env, g, &mut b2, cfg, db, pass);
        b.steps = b2.steps;
        match r {
            Ok(t) => return Ok(t),
            Err((mut f2, used2)) => {
                f2.tried.insert(0, format!("{label}: {}", f.tried.last().cloned().unwrap_or_default()));
                label = match pass {
                    Pass::Plain => "plain search",
                    Pass::Simp => "simplifier",
                    Pass::SimpNoCast => "simplifier without casts",
                };
                // what the simplifier did, over its passes
                used = Used { simp: used.simp || used2.simp, cast: used.cast || used2.cast };
                f = f2;
            }
        }
        prev = pass;
    }
    Err(f)
}

/// One pass of [`prove_goal`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pass {
    /// The search without the simplifier.
    Plain,
    /// With the simplifier (fact and target normal forms).
    Simp,
    /// With the simplifier, without its cast normal form.
    SimpNoCast,
}

/// What the simplifier did in a failed pass: it rewrote a fact or the
/// target (and the search failed, or its proof was rejected), and it used
/// the cast normal form.
#[derive(Clone, Copy, Default)]
struct Used {
    simp: bool,
    cast: bool,
}

/// Goals whose target reads back to at most this many nodes run with the
/// simplifier first ([`prove_goal`]).
const SIMP_FIRST_MAX_NODES: u64 = 120;

/// [`SIMP_FIRST_MAX_NODES`], or `SANDBLASTER_SIMP_FIRST_MAX` (0: never
/// first).
fn simp_first_max() -> u64 {
    static M: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *M.get_or_init(|| std::env::var("SANDBLASTER_SIMP_FIRST_MAX").ok().and_then(|v| v.parse().ok()).unwrap_or(SIMP_FIRST_MAX_NODES))
}

/// When the simplifier runs (`SANDBLASTER_SIMP`: `fallback`, the default:
/// first for small goals, after the plain search otherwise; `first` or
/// `off`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum SimpMode {
    Fallback,
    First,
    Off,
}

fn simp_mode() -> SimpMode {
    static M: std::sync::OnceLock<SimpMode> = std::sync::OnceLock::new();
    *M.get_or_init(|| match std::env::var("SANDBLASTER_SIMP").as_deref() {
        Ok("first") => SimpMode::First,
        Ok("off") => SimpMode::Off,
        _ => SimpMode::Fallback,
    })
}

/// [`prove_goal`], with or without the simplifier. The error says whether
/// a retry without it may help (the simplifier ran, and the search failed
/// or the kernel rejected its proof).
fn prove_goal_with(env: &Env, g: &Goal, b: &mut Budget, cfg: &AutoConfig, db: &LemmaDb, pass: Pass) -> Result<Tm, (AutoFailure, Used)> {
    let depth = g.ctx.depth().0;
    let mut e = Engine::new(env, b, cfg, db, g.hints.clone(), depth);
    let no_simp = pass == Pass::Plain;
    e.no_simp = no_simp;
    e.no_cast = pass == Pass::SimpNoCast;
    // `SANDBLASTER_AUTO_TRACE_ID=n`: trace only the goal of obligation `n`
    if let Ok(id) = std::env::var("SANDBLASTER_AUTO_TRACE_ID") {
        e.trace = id.parse::<u32>().ok() == Some(g.id.0);
    }
    // `SANDBLASTER_AUTO_TRACE_LINE=n`: trace only the goals whose span starts on line `n`
    if let Ok(line) = std::env::var("SANDBLASTER_AUTO_TRACE_LINE") {
        e.trace = line.parse::<u32>().ok() == Some(g.span.lo.0);
    }
    let mut st = St::new(env, &g.ctx, cfg.max_split_depth);
    for (l, entry) in g.ctx.entries.iter().enumerate() {
        if crate::elab::fact_hidden(l as u32) {
            continue;
        }
        if e.is_prop(&entry.ty, depth) {
            let origin = g.facts.iter().find(|f| f.lvl.0 == l as u32).map(|f| f.origin.clone());
            st.add_ctx_fact(l as u32, entry.ty.clone(), Origin::Goal(origin));
        }
    }
    if e.trace {
        for f in &st.facts {
            eprintln!("[auto] goal fact h{}: {}", f.lvl, e.show(&st, &f.ty));
        }
        eprintln!("[auto] goal target (obligation {}): {}", g.id.0, e.show(&st, &g.target));
    }
    let result = e.prove_root(st, g);
    // exhaustion (budget, deadline, memory) is a failure, even when a term
    // was built at the last moment
    let result = match result {
        Ok(Some(_)) if !super::meter::settle(e.b) || super::meter::exhausted().is_some() => Err(Stop::Budget),
        r => r,
    };
    match result {
        Ok(Some(t)) => {
            if cfg.self_check {
                let mut cb = Budget { steps: e.b.steps.max(1_000_000) };
                let mut first = env.check(&g.ctx, &t, &g.target, &mut cb);
                // the check of a found proof is not the search: a proof whose
                // check needs more evaluation than the goal had left (a large
                // unfolded body) is checked again with the kernel's own means
                // before it counts as rejected (§15 S5 X8: `Eval(OutOfFuel)`)
                if matches!(&first, Err(err) if matches!(err.kind, KernelErrorKind::Eval(EvalError::OutOfFuel))) {
                    let mut big = Budget { steps: 2_000_000_000 };
                    first = env.check(&g.ctx, &t, &g.target, &mut big);
                }
                if let Err(err) = first {
                    // Re-derive stale certificates of quoted proofs, then retry.
                    let mut rb = Budget { steps: e.b.steps.min(200_000_000) };
                    let (t2, n) = super::repair::repair(env, &g.ctx, &t, &mut rb);
                    let mut cb = Budget { steps: e.b.steps.max(1_000_000) };
                    if n > 0 && env.check(&g.ctx, &t2, &g.target, &mut cb).is_ok() {
                        return Ok(t2);
                    }
                    // then the ill-typed proof slots (a proof read back from
                    // its value, `refl(Bool, c)` for `c == true`): re-proved
                    // from the context, and checked again
                    let mut rb = Budget { steps: e.b.steps.min(200_000_000) };
                    let (t3, n3) = super::repair::repair_validated(env, &g.ctx, &t2, &mut rb);
                    let mut cb = Budget { steps: e.b.steps.max(1_000_000) };
                    let r3 = env.check(&g.ctx, &t3, &g.target, &mut cb);
                    if n3 > 0 && r3.is_ok() {
                        return Ok(t3);
                    }
                    if e.trace {
                        eprintln!("[auto] after {n} + {n3} repair(s): {:?}", r3.err().map(|x| x.to_string()));
                    }
                    if e.trace {
                        let names: Vec<sandblaster_kernel::term::Name> = g.ctx.entries.iter().map(|e| e.name.clone()).collect();
                        eprintln!("[auto] the produced proof was rejected by the kernel: {err}\n    proof: {}", truncate(sandblaster_kernel::syntax::printer::print_term_bounded(env, &names, &t, 200000), 200000));
                    }
                    let used = Used { simp: !no_simp && e.simp_used, cast: e.cast_used };
                    let mut f = e.failure(g);
                    f.tried.push(format!("internal error: the produced proof was rejected by the kernel: {err}"));
                    return Err((f, used));
                }
            }
            Ok(t)
        }
        Ok(None) => {
            let used = Used { simp: !no_simp && e.simp_used, cast: e.cast_used };
            Err((e.failure(g), used))
        }
        Err(Stop::Budget) => {
            let note = if e.nodes > cfg.max_nodes { format!("budget exhausted (search node limit {})", cfg.max_nodes) } else { super::meter::failure_note() };
            // a deadline or memory stop leaves nothing for a retry
            let retry = matches!(super::meter::exhausted(), None | Some(super::meter::Exhaustion::Steps));
            let used = Used { simp: !no_simp && e.simp_used && retry, cast: e.cast_used && retry };
            let mut f = e.failure(g);
            f.tried.push(note);
            Err((f, used))
        }
    }
}

impl<'a> Engine<'a> {
    /// The root: hints, then [`Engine::solve`].
    fn prove_root(&mut self, mut st: St, g: &Goal) -> R<Option<Tm>> {
        for h in g.hints.clone() {
            match h {
                Hint::Exact(t) => {
                    self.note("exact hint");
                    let t = shift(&t, (st.depth() - self.goal_depth) as i64);
                    let p = self.promote(&st, &g.target, t);
                    return Ok(Some(st.finish(p)));
                }
                Hint::Lemma(t) => {
                    let d = st.depth();
                    let tm = shift(&t, (d - self.goal_depth) as i64);
                    if let Some(ty) = self.infer_irr(&st, &tm)? {
                        self.note("lemma hint as a fact");
                        st.push_fact(self.env, ty, tm, Origin::Hint);
                    }
                }
                Hint::Witness(ws) => self.witness = Some(ws),
                _ => {}
            }
        }
        if let Some(Hint::Cases { var, lo, hi }) = g.hints.iter().find(|h| matches!(h, Hint::Cases { .. })).cloned()
            && self.cfg.mode.allows_splits()
        {
            self.note(format!("cases hint on level {} in [{lo}, {hi})", var.0));
            let body = self.enumerate(&st, var.0, &lo, &hi, g.target.clone(), false)?;
            return Ok(body.map(|b| st.finish(b)));
        }
        let body = self.solve_in(&mut st, g.target.clone(), false)?;
        Ok(body.map(|b| st.finish(b)))
    }

    /// Build the failure report.
    pub fn failure(&mut self, g: &Goal) -> AutoFailure {
        super::report::failure(self, g)
    }
}
