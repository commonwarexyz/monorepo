//! Counterexamples to the obligations of an optimizer residual that did not
//! re-prove (design §4: the fallback rules).
//!
//! A residual (or helper) the optimizer prints is elaborated again, and
//! every proof slot is re-proven. When an obligation is not re-proven there
//! are two possible reasons:
//!
//! * the obligation holds, but the provers do not find a proof in the
//!   residual's context (the driver decided a test with its own procedure
//!   and the residual no longer prints it, say). This is an incompleteness:
//!   the function keeps its source, a *proven fallback*, recorded in the
//!   report — not an optimizer fault;
//! * the obligation is false: the residual performs an operation outside its
//!   domain on some input where the source does not (a partial read hoisted
//!   out of its guard, a helper `requires` its call sites do not establish).
//!   The optimizer produced something wrong: an *internal inconsistency*, an
//!   optimizer fault (a warning; a build error under strict options).
//!
//! The two are told apart by a definite counterexample: values for the
//! obligation's context (parameters, `let`s evaluated) under which every
//! hypothesis in the context evaluates to true and the goal evaluates to
//! false, all by kernel evaluation of closed terms. Only a counterexample
//! found makes the failure a fault; without one it is an incompleteness.
//! The search is bounded and incomplete (random and boundary values of the
//! scalar, slice, array and inductive types it can build), and it never
//! decides what is emitted: either way the residual is refused and the
//! source is printed. A comparison that is not between two closed values
//! (a primitive outside its domain stays stuck) is never a verdict.
//!
//! The values are drawn so that the hypotheses can hold: besides a fixed
//! pool of boundary values, every integer literal of the hypotheses and
//! the goal (and its neighbours `c - 1`, `c + 1`) is a candidate for every
//! scalar, and the small ones are candidate lengths of slices and lists. A
//! helper behind `#[requires(xs.len() >= 8)]` or `#[requires(k == 12345)]`
//! is then refuted like one without a `requires`. A counterexample found is
//! checked by evaluation alone, so a satisfying assignment of hypotheses
//! from which linear arithmetic derives the goal's negation is already a
//! counterexample: no separate linear-arithmetic verdict is needed.
//!
//! Hypotheses the elaborator binds as relevant facts (the hint facts of a
//! proof slot, `Scope::hint_facts`) are judged like irrelevant ones, and an
//! irrelevant datum (a ghost value, an inductive proposition) is built like
//! a parameter: a counterexample must still satisfy every one of them.
//!
//! [`annotate`] is called by the elaborator on every failed obligation
//! (`elab/obl.rs`) and does nothing unless the optimizer enabled it for the
//! elaboration of one of its residuals ([`Enable`]).

use std::cell::Cell;
use std::rc::Rc;

use num_bigint::BigInt;
use sandblaster_kernel::api::{Ctx, Env};
use sandblaster_kernel::term::{IndId, Lvl, Rel, Term, Tm, Width};
use sandblaster_kernel::value::{Arg, Budget, Closure, EnvEntry, V, VEnv, Value};

use crate::prover::AutoFailure;

/// The prefix of the note a counterexample adds to the failure.
pub const REFUTED: &str = "refuted: the goal is false at";

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
}

/// Enables [`annotate`] while alive (the elaboration of an optimizer
/// residual or helper).
pub struct Enable(bool);

impl Enable {
    pub fn new() -> Enable {
        Enable(ACTIVE.with(|c| c.replace(true)))
    }
}

impl Default for Enable {
    fn default() -> Self {
        Enable::new()
    }
}

impl Drop for Enable {
    fn drop(&mut self) {
        let prev = self.0;
        ACTIVE.with(|c| c.set(prev));
    }
}

/// Searches a counterexample to the failed obligation `target` (a term in
/// `ctx`) when enabled; a found one is recorded as the first note of
/// `failure` ([`REFUTED`]). `complete`: every hypothesis of the goal is a
/// binder of `ctx` (none is only a hint of the proof slot, which the search
/// would not see: then it does not search).
pub fn annotate(env: &Env, ctx: &Ctx, target: &Tm, complete: bool, mut failure: AutoFailure) -> AutoFailure {
    if !ACTIVE.with(|c| c.get()) || !complete {
        return failure;
    }
    let t0 = std::time::Instant::now();
    let found = counterexample(env, ctx, target);
    if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() || std::env::var_os("SANDBLASTER_OPT_TIMING").is_some() {
        eprintln!("opt: refute: {} in {:?} (context of {} entries)", if found.is_some() { "a counterexample" } else { "none found" }, t0.elapsed(), ctx.entries.len());
    }
    if let Some(cx) = found {
        failure.tried.insert(0, format!("{REFUTED} {cx}"));
    }
    failure
}

/// Whether a failure note records a counterexample.
pub fn is_refuted(note: &str) -> bool {
    note.contains(REFUTED)
}

/// Relevant entries of a context the search instantiates at most.
const MAX_VARS: usize = 64;
/// Random assignments tried (after the all-first-choice one).
const ROUNDS: u32 = 256;
/// Kernel steps of the whole search.
const TOTAL_STEPS: u64 = 20_000_000;
/// Kernel steps of one evaluation.
const EVAL_STEPS: u64 = 400_000;

/// A counterexample to `target` in `ctx` (a description of the values),
/// if the bounded search finds one.
pub fn counterexample(env: &Env, ctx: &Ctx, target: &Tm) -> Option<String> {
    let entries = &ctx.entries;
    let rel = entries.iter().filter(|e| e.rel == Rel::Rel && e.def.is_none()).count();
    if rel > MAX_VARS {
        return None;
    }
    // the context's entries as terms of their own depth
    let tys: Vec<Tm> = entries.iter().enumerate().map(|(i, e)| env.quote(Lvl(i as u32), &e.ty, false)).collect();
    let defs: Vec<Option<Tm>> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| match &e.def {
            Some(Arg::Rel(v)) => Some(env.quote(Lvl(i as u32), v, false)),
            _ => None,
        })
        .collect();
    let mut s = Search { env, rng: 0x9e37_79b9_7f4a_7c15, first: true, total: TOTAL_STEPS, ids: Ids::new(env), hints: Vec::new(), lens: Vec::new() };
    s.seed(ctx, &tys, target);
    for round in 0..=ROUNDS {
        s.first = round == 0;
        match s.assignment(ctx, &tys, &defs, target) {
            Outcome::Refuted(desc) => return Some(desc),
            Outcome::GiveUp => return None,
            Outcome::Next => {}
        }
        if s.total == 0 {
            return None;
        }
    }
    None
}

enum Outcome {
    Refuted(String),
    /// This assignment says nothing (a hypothesis false or undecided).
    Next,
    /// The context has an entry the search cannot build or judge.
    GiveUp,
}

struct Ids {
    list: Option<IndId>,
    unit: Option<IndId>,
}

impl Ids {
    fn new(env: &Env) -> Ids {
        Ids { list: env.lookup_ind("List"), unit: env.lookup_ind("Unit") }
    }
}

struct Search<'a> {
    env: &'a Env,
    rng: u64,
    /// The first assignment takes every first choice (zeros, empty lists).
    first: bool,
    total: u64,
    ids: Ids,
    /// The integer literals of the hypotheses and the goal, with their
    /// neighbours (candidates for every scalar, [`Search::seed`]).
    hints: Vec<BigInt>,
    /// The small ones among them: candidate lengths of slices and lists.
    lens: Vec<usize>,
}

/// Literal hints kept at most (the first ones found).
const MAX_HINTS: usize = 48;
/// The longest slice or list a length hint builds.
const MAX_HINT_LEN: usize = 64;
/// Kernel steps of the evaluations that collect the hints (out of
/// [`TOTAL_STEPS`]).
const SEED_STEPS: u64 = 2_000_000;

fn erased() -> Closure {
    Closure { env: VEnv::default(), body: Rc::new(Term::Erased) }
}

impl Search<'_> {
    fn next(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn pick(&mut self, n: usize) -> usize {
        if self.first || n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }

    /// Collects the literal hints: every integer literal of the context's
    /// hypotheses (irrelevant entries, and relevant ones whose type is an
    /// equation) and of the goal, read from their terms and from their
    /// transparent evaluation in the context (so a constant such as
    /// `MAX_HEIGHT` counts by its value), each with its neighbours.
    fn seed(&mut self, ctx: &Ctx, tys: &[Tm], target: &Tm) {
        let mut lits: Vec<BigInt> = Vec::new();
        let add = |t: &Tm, lits: &mut Vec<BigInt>| {
            crate::elab::tm::any_node(t, &mut |n| {
                if let Term::Lit { n, .. } = n
                    && !lits.contains(n)
                {
                    lits.push(n.clone());
                }
                lits.len() >= MAX_HINTS
            });
        };
        // the goal first (its literals are kept when there are too many)
        let mut sources: Vec<(Lvl, Tm)> = vec![(Lvl(ctx.entries.len() as u32), target.clone())];
        for (i, e) in ctx.entries.iter().enumerate() {
            if e.def.is_some() {
                continue;
            }
            if e.rel == Rel::Irr || matches!(&*e.ty, Value::Eq { .. }) {
                sources.push((Lvl(i as u32), tys[i].clone()));
            }
        }
        for (_, t) in &sources {
            add(t, &mut lits);
        }
        // (the evaluations take their own share of the search's steps)
        let total = self.total;
        let share = SEED_STEPS.min(total);
        self.total = share;
        let venv = self.env.ctx_venv(ctx);
        for (d, t) in &sources {
            if self.total == 0 || lits.len() >= MAX_HINTS {
                break;
            }
            // the context's environment truncated to the term's depth
            let es: Vec<EnvEntry> = venv.0.iter().take(d.0 as usize).cloned().collect();
            if let Some(v) = self.eval(&VEnv(Rc::new(es)), t) {
                add(&self.env.quote(*d, &v, false), &mut lits);
            }
        }
        self.total = total - (share - self.total);
        for c in lits {
            for x in [&c - 1, c.clone(), &c + 1] {
                if !self.hints.contains(&x) {
                    if let Ok(k) = usize::try_from(&x)
                        && k <= MAX_HINT_LEN
                        && !self.lens.contains(&k)
                    {
                        self.lens.push(k);
                    }
                    self.hints.push(x);
                }
            }
        }
    }

    /// A length of a slice or list: one of `0..=4`, or (half the time,
    /// when there are any) a length hint.
    fn len(&mut self) -> usize {
        if !self.first && !self.lens.is_empty() && self.next().is_multiple_of(2) {
            let i = self.pick(self.lens.len());
            return self.lens[i];
        }
        self.pick(5)
    }

    fn eval(&mut self, venv: &VEnv, t: &Tm) -> Option<V> {
        let mut b = Budget { steps: EVAL_STEPS.min(self.total) };
        let start = b.steps;
        let r = self.env.eval_transparent(venv, Lvl(venv.0.len() as u32), t, &mut b);
        self.total = self.total.saturating_sub(start - b.steps);
        r.ok()
    }

    fn inst(&mut self, c: &Closure, e: EnvEntry) -> Option<V> {
        let mut es = (*c.env.0).clone();
        es.push(e);
        let venv = VEnv(Rc::new(es));
        self.eval(&venv, &c.body)
    }

    fn conv(&mut self, a: &V, b: &V) -> Option<bool> {
        let mut bud = Budget { steps: EVAL_STEPS.min(self.total) };
        let start = bud.steps;
        let r = self.env.conv(Lvl(0), a, b, &mut bud);
        self.total = self.total.saturating_sub(start - bud.steps);
        r.ok()
    }

    /// One assignment of the context: build, then judge.
    fn assignment(&mut self, ctx: &Ctx, tys: &[Tm], defs: &[Option<Tm>], target: &Tm) -> Outcome {
        let mut es: Vec<EnvEntry> = Vec::with_capacity(tys.len());
        let mut shown: Vec<String> = Vec::new();
        for (i, e) in ctx.entries.iter().enumerate() {
            let venv = VEnv(Rc::new(es.clone()));
            if let Some(d) = &defs[i] {
                // a `let`: its value
                let Some(v) = self.eval(&venv, d) else { return Outcome::GiveUp };
                es.push(EnvEntry::Rel(v));
                continue;
            }
            if e.def.is_some() {
                // an irrelevant `let` (a proof derived from earlier entries)
                es.push(EnvEntry::Irr(erased()));
                continue;
            }
            let Some(ty) = self.eval(&venv, &tys[i]) else { return Outcome::GiveUp };
            match e.rel {
                Rel::Irr => {
                    // a hypothesis: it must hold
                    match self.holds(&ty) {
                        Some(true) => es.push(EnvEntry::Irr(erased())),
                        Some(false) => return Outcome::Next,
                        None if self.is_prop(&ty) => return Outcome::Next,
                        None => {
                            // an irrelevant datum (a ghost value, a proof of
                            // an inductive proposition): built like a
                            // parameter (a constructor's invariants hold),
                            // bound as the entry's closure
                            let Some(v) = self.value_of(&ty, 3) else { return Outcome::GiveUp };
                            if !ground(&v) {
                                return Outcome::GiveUp;
                            }
                            let t = self.env.quote(Lvl(0), &v, false);
                            shown.push(format!("{} = {} (ghost)", e.name, self.env.print_term(&[], &t)));
                            es.push(EnvEntry::Irr(Closure { env: VEnv::default(), body: t }));
                        }
                    }
                }
                // a relevant fact (a hint fact of the proof slot, bound for
                // the prover): a hypothesis too, proven by `refl`
                Rel::Rel if matches!(&*ty, Value::Eq { .. }) => match self.value_of(&ty, 0) {
                    Some(p) => es.push(EnvEntry::Rel(p)),
                    None => return Outcome::Next,
                },
                Rel::Rel => {
                    let Some(v) = self.value_of(&ty, 3) else { return Outcome::GiveUp };
                    if !ground(&v) {
                        return Outcome::GiveUp;
                    }
                    shown.push(format!("{} = {}", e.name, self.env.print_term(&[], &self.env.quote(Lvl(0), &v, false))));
                    es.push(EnvEntry::Rel(v));
                }
            }
        }
        let venv = VEnv(Rc::new(es));
        let Some(goal) = self.eval(&venv, target) else { return Outcome::Next };
        match self.holds(&goal) {
            Some(false) => Outcome::Refuted(if shown.is_empty() { "(no parameters)".into() } else { shown.join(", ") }),
            _ => Outcome::Next,
        }
    }

    /// Whether the proposition `p` (closed) holds: `None` when it is not a
    /// comparison of closed values the search can judge.
    fn holds(&mut self, p: &V) -> Option<bool> {
        match &**p {
            Value::Eq { lhs, rhs, .. } => {
                if !ground(lhs) || !ground(rhs) {
                    return None;
                }
                self.conv(lhs, rhs)
            }
            Value::Ind { ind, .. } if Some(*ind) == self.ids.unit => Some(true),
            Value::Ind { ind, .. } if *ind == self.env.empty_ind() => Some(false),
            // a conjunction (`And P Q` is `Σ(_ : P). Q`)
            Value::Sigma { fst, snd, .. } => {
                let a = self.holds(fst)?;
                if !a {
                    return Some(false);
                }
                let q = self.inst(snd, EnvEntry::Irr(erased()))?;
                self.holds(&q)
            }
            _ => None,
        }
    }

    /// Whether `p` looks like a proposition the search cannot judge (as
    /// opposed to a datum): an equation or a conjunction.
    fn is_prop(&self, p: &V) -> bool {
        matches!(&**p, Value::Eq { .. } | Value::Sigma { .. })
            || matches!(&**p, Value::Ind { ind, .. } if Some(*ind) == self.ids.unit || *ind == self.env.empty_ind())
    }

    fn int(&mut self, w: Width) -> V {
        let pool: Vec<BigInt> = match w.bits() {
            Some(bits) => {
                let max = (BigInt::from(1) << bits) - 1;
                let mut p: Vec<BigInt> = [0u64, 1, 2, 3, 4, 7, 8, 16, 62, 63, 64, 100, 127, 128, 255, 256, 1000, 65535, 65536].iter().map(|x| BigInt::from(*x)).filter(|x| *x <= max).collect();
                p.push(max.clone());
                p.push(&max - 1);
                p.push(&max >> 1);
                p.push(BigInt::from(self.next()) & &max);
                p
            }
            None => [-2i64, -1, 0, 1, 2, 3, 7, 64, 100, 1 << 40].iter().map(|x| BigInt::from(*x)).collect(),
        };
        // half the time (when there are any), a literal hint in range
        if !self.first && self.next().is_multiple_of(2) {
            let fits = |x: &BigInt| match w.bits() {
                Some(b) => *x >= BigInt::from(0) && *x < (BigInt::from(1) << b),
                None => true,
            };
            let hs: Vec<BigInt> = self.hints.iter().filter(|x| fits(x)).cloned().collect();
            if !hs.is_empty() {
                let i = self.pick(hs.len());
                return Rc::new(Value::Lit { w, n: hs[i].clone() });
            }
        }
        let i = self.pick(pool.len());
        Rc::new(Value::Lit { w, n: pool[i].clone() })
    }

    fn list(&mut self, elem: &V, len: usize, depth: u32) -> Option<V> {
        let list = self.ids.list?;
        let mut acc: V = Rc::new(Value::Ctor { ind: list, ctor: 0, params: vec![elem.clone()], args: vec![] });
        let mut items = Vec::with_capacity(len);
        for _ in 0..len {
            items.push(self.value_of(elem, depth.saturating_sub(1))?);
        }
        for x in items.into_iter().rev() {
            acc = Rc::new(Value::Ctor { ind: list, ctor: 1, params: vec![elem.clone()], args: vec![Arg::Rel(x), Arg::Rel(acc)] });
        }
        Some(acc)
    }

    /// A value of the closed type `ty` (`None`: a type it cannot build).
    fn value_of(&mut self, ty: &V, depth: u32) -> Option<V> {
        match &**ty {
            Value::IntTy(w) => Some(self.int(*w)),
            Value::Ind { ind, params } if Some(*ind) == self.ids.list => {
                let n = self.len();
                self.list(params.first()?, n, depth)
            }
            // an equation between closed values that holds: `refl`
            Value::Eq { ty: a, lhs, rhs } => {
                if !ground(lhs) || !ground(rhs) || self.conv(lhs, rhs) != Some(true) {
                    return None;
                }
                Some(Rc::new(Value::Refl { ty: a.clone(), val: lhs.clone() }))
            }
            Value::Ind { ind, params } => self.ctor(*ind, params, depth),
            Value::Sigma { fst, snd_rel, snd, .. } => {
                // a slice `Σ(n : usize). Σ(l : List T). SliceOk T n l`: a
                // list and its length
                if let (Value::IntTy(Width::Usize), Rel::Rel) = (&**fst, snd_rel) {
                    let probe = self.inst(snd, EnvEntry::Rel(Rc::new(Value::Lit { w: Width::Usize, n: BigInt::from(0) })))?;
                    if let Value::Sigma { fst: lt, snd_rel: Rel::Irr, .. } = &*probe
                        && let Value::Ind { ind, params } = &**lt
                        && Some(*ind) == self.ids.list
                    {
                        let k = self.len();
                        let l = self.list(params.first()?, k, depth)?;
                        let n = Rc::new(Value::Lit { w: Width::Usize, n: BigInt::from(k) });
                        let inner = Rc::new(Value::Pair { fst: l, snd: Arg::Irr(erased()) });
                        return Some(Rc::new(Value::Pair { fst: n, snd: Arg::Rel(inner) }));
                    }
                }
                // an array `Σ(l : List T). Eq(Int, len l, N)`: `N` elements
                if let (Value::Ind { ind, params }, Rel::Irr) = (&**fst, snd_rel)
                    && Some(*ind) == self.ids.list
                {
                    let elem = params.first()?.clone();
                    let empty = self.list(&elem, 0, depth)?;
                    let eq = self.inst(snd, EnvEntry::Rel(empty))?;
                    let Value::Eq { rhs, .. } = &*eq else { return None };
                    let Value::Lit { n, .. } = &**rhs else { return None };
                    let k: usize = n.try_into().ok().filter(|k: &usize| *k <= 64)?;
                    let l = self.list(&elem, k, depth)?;
                    return Some(Rc::new(Value::Pair { fst: l, snd: Arg::Irr(erased()) }));
                }
                // a pair of data (its second part may depend on the first)
                let a = self.value_of(fst, depth)?;
                match snd_rel {
                    Rel::Rel => {
                        let t2 = self.inst(snd, EnvEntry::Rel(a.clone()))?;
                        let b = self.value_of(&t2, depth)?;
                        Some(Rc::new(Value::Pair { fst: a, snd: Arg::Rel(b) }))
                    }
                    Rel::Irr => {
                        // a datum with a proposition about it: it must hold
                        let p = self.inst(snd, EnvEntry::Rel(a.clone()))?;
                        (self.holds(&p)? ).then(|| Rc::new(Value::Pair { fst: a, snd: Arg::Irr(erased()) }))
                    }
                }
            }
            _ => None,
        }
    }

    /// A constructor value of the inductive `ind` at `params` (its
    /// irrelevant fields, invariants, must hold).
    fn ctor(&mut self, ind: IndId, params: &[V], depth: u32) -> Option<V> {
        let decl = self.env.inductive_decl(ind)?;
        if decl.ctors.is_empty() {
            return None;
        }
        // near the depth limit, prefer a constructor without a recursive field
        let mut order: Vec<usize> = (0..decl.ctors.len()).collect();
        let start = self.pick(order.len());
        order.rotate_left(start);
        for k in order {
            let c = &decl.ctors[k];
            let recursive = c.fields.iter().any(|(_, _, t)| matches!(&**t, Term::Ind { ind: i, .. } if *i == ind));
            if recursive && depth == 0 {
                continue;
            }
            let mut es: Vec<EnvEntry> = params.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
            let mut args = Vec::with_capacity(c.fields.len());
            let mut ok = true;
            for (_, rel, t) in &c.fields {
                let venv = VEnv(Rc::new(es.clone()));
                let Some(fty) = self.eval(&venv, t) else {
                    ok = false;
                    break;
                };
                match rel {
                    Rel::Rel => {
                        let Some(v) = self.value_of(&fty, depth.saturating_sub(1)) else {
                            ok = false;
                            break;
                        };
                        es.push(EnvEntry::Rel(v.clone()));
                        args.push(Arg::Rel(v));
                    }
                    Rel::Irr => {
                        if self.holds(&fty) != Some(true) {
                            ok = false;
                            break;
                        }
                        es.push(EnvEntry::Irr(erased()));
                        args.push(Arg::Irr(erased()));
                    }
                }
            }
            if ok {
                return Some(Rc::new(Value::Ctor { ind, ctor: k as u32, params: params.to_vec(), args }));
            }
        }
        None
    }
}

/// A closed first-order value: literals, constructors and pairs of them.
fn ground(v: &V) -> bool {
    match &**v {
        Value::Lit { .. } => true,
        Value::Ctor { args, .. } => args.iter().all(|a| match a {
            Arg::Rel(x) => ground(x),
            Arg::Irr(_) => true,
        }),
        Value::Pair { fst, snd } => {
            ground(fst)
                && match snd {
                    Arg::Rel(x) => ground(x),
                    Arg::Irr(_) => true,
                }
        }
        Value::Refl { .. } => true,
        _ => false,
    }
}
