//! Normalization by evaluation (DESIGN.md §5.3, §5.6, §5.7, §5.9).
//!
//! * Call-by-value for relevant arguments; irrelevant arguments, `Irr` let
//!   values, `Irr` pair components, prim proof slots and `Irr` constructor
//!   fields are kept as unevaluated [`Closure`]s and never forced (§5.3).
//! * Unfolding policy (§5.6), implemented by [`Ev::policy`]:
//!   - non-recursive, non-intrinsic globals unfold on demand (their closed
//!     body value is cached);
//!   - a recursive global applied to all `arity` arguments unfolds iff a
//!     *speculative* evaluation of its body (on a sub-budget, with the
//!     recursive globals under speculation folded) does not end in a value
//!     whose head is a match on a neutral or a partial checked primitive on
//!     a neutral; otherwise it is the neutral `Head::Global { def, args }`.
//!     Only globals whose speculation is in progress are folded (by
//!     definition order that is the global's own recursion); other recursive
//!     helpers in the body evaluate with the normal policy, so a head test
//!     such as `lt(len l, N)` on a concrete `l` decides. Exhausting the
//!     sub-budget keeps the application neutral (sound);
//!   - **ground recursion** (phase 3): if the speculation is stuck only
//!     because a folded recursive call is inspected (`match rec(t) ..`, a
//!     partial prim on it) and the recursion argument is ground (a closed
//!     constructor spine for structural recursion, a literal measure), the
//!     body is evaluated with the real policy, whose recursive calls are on
//!     ground arguments again — the recursion terminates, so non-tail
//!     recursion that inspects its own result computes on concrete data. In
//!     the optimizer's transparent mode an application to closed arguments
//!     whose speculation merely exhausts the sub-budget is evaluated the
//!     same way. A result that is still stuck keeps the application folded;
//!   - `DefKind::Intrinsic` globals unfold only when every relevant argument
//!     is a closed value (literals, constructors/pairs of closed values,
//!     types); in the `BvRefl` mode ([`Ev::bv`], DESIGN.md §9.8) they
//!     unfold on symbolic data too, and that mode is transparent (opaque
//!     definitions unfold);
//!   - **opaque** definitions (`DefDecl.opaque`) never unfold in the default
//!     mode used by checking and conversion (their defining equation is
//!     available through `Delta`/`Unfold`); this only loses completeness;
//!   - `eval_opaque` (optimizer) is the *transparent* mode: `DefDecl.opaque`
//!     is ignored and exactly the globals of the caller's opaque set stay
//!     folded (an empty set evaluates everything, DESIGN.md §5.6).
//! * `Rec` (only inside the body being checked by `add_def`) evaluates to the
//!   neutral `Head::Global { def: pending_id, args }`: the id is not in the
//!   environment yet, so it can never unfold. Committed bodies have every
//!   `Rec` replaced by an application of the global itself.
//! * `transport` reduces to its value iff its endpoints are convertible
//!   (§5.5; this is the only place evaluation calls conversion).
//! * Primitive applications compute on literals ([`crate::prim::eval_lits`])
//!   and otherwise go through the §5.7 simplifications, plus the evaluator-
//!   level rules that mention prelude functions: `index(take/drop(l, a), i)`
//!   with literal offsets, `from_le_bytes([cast_u8(x), cast_u8(x>>8), ..]) →
//!   x`, and `cast_u8(wshr(from_le_bytes(bs), 8k)) → bs[k]`.
//! * Fresh variables of type `Array(T, N)` (literal `N ≤ 256`) are introduced
//!   in their eta-expanded form `([index(fst x, 0), .., index(fst x, N−1)],
//!   snd x)`; this implements the fixed-length array eta of §5.9 (sound by
//!   extensionality of fixed-length lists) for every variable the kernel
//!   introduces (binders in checking and conversion, and contexts converted
//!   with [`crate::api::Env::ctx_venv`]).
//! * Every step consumes budget; exhaustion is [`EvalError::OutOfFuel`].
//!
//! Performance shortcuts (each computes exactly the value plain unfolding
//! computes; tested in `tests/eval_opt.rs`):
//! * **Speculation reuse** ([`Ev::resume`]): a successful speculative
//!   unfolding whose folded recursive calls occur only at the top of its
//!   value — the value *is* the folded call (tail recursion), or a
//!   constructor/pair with folded calls as direct fields — is completed by
//!   unfolding just those calls instead of re-evaluating the body (reference
//!   counts prove there is no other occurrence). This halves the cost of
//!   loops and list-producing recursion.
//! * **Direct indexing**: `seq::index T l i` with a literal `i` into a
//!   constructor spine at least `i + 1` long is its element (what the
//!   definition's recursion computes), without one unfolding per element.
//! * Tail steps own their environment and extend it in place when it is not
//!   shared.
//! * **Term DAGs** ([`EvalMemo`]): a shared term node (`Rc::strong_count >
//!   1`) evaluated in a registered environment (an API call's root
//!   environment, a checking context, a root closure instantiation by
//!   conversion/quoting/checking, and their let/arm extensions) is evaluated
//!   once; a definition body that is a DAG (`DefInfo::shared`) is unfolded
//!   with a memo scoped to that unfolding. Without this a term DAG (read
//!   back from a symbolic value, or produced by substitution) is evaluated
//!   as the tree it unfolds to.

use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive};

use crate::api::Env;
use crate::env::DefInfo;
use crate::prim::{self, LitOut, Simp};
use crate::term::{DefKind, GlobalId, Idx, IndId, Lvl, PrimOp, Rel, Sort, Term, Tm, Width};
use crate::util::{arg_entry, irr_var_closure, tick, venv_extend, venv_extend_owned, venv_get, venv_push, venv_push_owned};
use crate::value::{Arg, Budget, Closure, Elim, EnvEntry, EvalError, Head, Neutral, V, VEnv, Value};

type R<T> = Result<T, EvalError>;

/// Sub-budget of one speculative unfolding test (§5.6). Exhausting it keeps
/// the application neutral (which is always sound); exhausting the caller's
/// budget is an error.
pub(crate) const SPEC_LIMIT: u64 = 1 << 20;

/// Largest array length that is eta-expanded (§5.9).
pub(crate) const ARRAY_ETA_MAX: u32 = 256;

/// Build a neutral value.
pub(crate) fn neu(head: Head, spine: Vec<Elim>) -> V {
    Rc::new(Value::Neu(Neutral { head, spine }))
}

/// The neutral variable at level `l`.
pub(crate) fn var_v(l: Lvl) -> V {
    neu(Head::Var(l), Vec::new())
}

/// Placeholder produced only for ill-typed input (never for checked terms).
pub(crate) fn garbage() -> V {
    neu(Head::Absurd { ty: Rc::new(Value::Sort(Sort::Type)) }, Vec::new())
}

pub(crate) fn clone_head(h: &Head) -> Head {
    match h {
        Head::Var(l) => Head::Var(*l),
        Head::Global { def, args } => Head::Global { def: *def, args: args.clone() },
        Head::Prim { op, args, proofs } => Head::Prim { op: *op, args: args.clone(), proofs: proofs.clone() },
        Head::Absurd { ty } => Head::Absurd { ty: ty.clone() },
        Head::Transport { ty, lhs, rhs, motive, val } => {
            Head::Transport { ty: ty.clone(), lhs: lhs.clone(), rhs: rhs.clone(), motive: motive.clone(), val: val.clone() }
        }
        Head::Axiom { ax, args } => Head::Axiom { ax: *ax, args: args.clone() },
    }
}

pub(crate) fn clone_elim(e: &Elim) -> Elim {
    match e {
        Elim::App(a) => Elim::App(a.clone()),
        Elim::Fst => Elim::Fst,
        Elim::Snd => Elim::Snd,
        Elim::Match { ind, params, motive, arms } => {
            Elim::Match { ind: *ind, params: params.clone(), motive: motive.clone(), arms: arms.clone() }
        }
    }
}

/// Extend a neutral with one more eliminator.
fn push_elim(n: &Neutral, e: Elim) -> V {
    let mut spine: Vec<Elim> = n.spine.iter().map(clone_elim).collect();
    spine.push(e);
    neu(clone_head(&n.head), spine)
}

/// The §5.6 "stuck at the head" test on the result of a speculative
/// unfolding.
fn stuck_at_head(v: &V) -> bool {
    match &**v {
        Value::Neu(n) => {
            n.spine.iter().any(|e| matches!(e, Elim::Match { .. })) || matches!(&n.head, Head::Prim { op, .. } if prim::is_partial(*op))
        }
        _ => false,
    }
}

/// Closed values (§5.6 intrinsic rule): literals and constructors/pairs of
/// closed values; types count as closed.
fn is_closed(v: &V) -> bool {
    match &**v {
        Value::Lit { .. } | Value::Sort(_) | Value::IntTy(_) | Value::Ind { .. } => true,
        Value::Ctor { args, .. } => args.iter().all(|a| match a {
            Arg::Rel(v) => is_closed(v),
            Arg::Irr(_) => true,
        }),
        Value::Pair { fst, snd } => {
            is_closed(fst)
                && match snd {
                    Arg::Rel(v) => is_closed(v),
                    Arg::Irr(_) => true,
                }
        }
        _ => false,
    }
}

/// Every relevant argument is a closed value.
fn closed_args(args: &[Arg]) -> bool {
    args.iter().all(|a| match a {
        Arg::Rel(v) => is_closed(v),
        Arg::Irr(_) => true,
    })
}

/// Is the stuck speculative value `v` blocked by one of the folded
/// applications `folds` — its head is a folded call, or a primitive whose
/// operands (through primitive heads) reach one? Bounded: a large value
/// counts as blocked (the caller then merely tries the real evaluation).
fn blocked_by_fold(v: &V, folds: &[V]) -> bool {
    let defs: Vec<GlobalId> = folds
        .iter()
        .filter_map(|f| match &**f {
            Value::Neu(Neutral { head: Head::Global { def, .. }, .. }) => Some(*def),
            _ => None,
        })
        .collect();
    let mut fuel = 4096u32;
    fn go(v: &V, defs: &[GlobalId], fuel: &mut u32) -> bool {
        if *fuel == 0 {
            return true;
        }
        *fuel -= 1;
        match &**v {
            Value::Neu(Neutral { head: Head::Global { def, .. }, .. }) => defs.contains(def),
            Value::Neu(Neutral { head: Head::Prim { args, .. }, .. }) => args.iter().any(|a| go(a, defs, fuel)),
            _ => false,
        }
    }
    go(v, &defs, &mut fuel)
}

/// One step of tail evaluation: either a value, or a term to continue with
/// (in place of the current one).
enum Step {
    Done(V),
    Continue(VEnv, Tm),
    /// Apply the unfolding policy to a global and all its arguments (a tail
    /// call produced by [`Ev::resume`]).
    Apply(GlobalId, Vec<Arg>),
}

/// The evaluator.
///
/// * `opaque`: `None` is the default (checking) mode, in which the globals
///   declared opaque (`DefDecl.opaque`) stay folded; `Some(set)` is the
///   optimizer's transparent mode, in which exactly the globals of `set`
///   stay folded.
/// * `bv`: the `BvRefl` mode (§9.8): intrinsics unfold on symbolic data.
/// * `spec` lists the recursive globals whose speculative unfolding test is
///   in progress (their applications stay folded; empty outside
///   speculation).
pub(crate) struct Ev<'e> {
    pub env: &'e Env,
    pub opaque: Option<&'e dyn Fn(GlobalId) -> bool>,
    pub bv: bool,
    /// The opaque set is known to be empty (fully transparent mode), so
    /// definition values can be cached for this mode.
    pub transparent: bool,
    spec: Vec<GlobalId>,
    folded: u64,
    /// The folded applications created during a speculation (see
    /// [`Ev::speculate`]), in creation order.
    folds: Vec<V>,
    /// Memo of shared term nodes evaluated in registered root environments
    /// (see [`EvalMemo`]); never used while speculating.
    memo: Option<Rc<std::cell::RefCell<EvalMemo>>>,
}

/// Memo of the values of **shared term nodes** (`Rc::strong_count > 1`,
/// e.g. a term DAG read back from a symbolic value, or produced by
/// substitution) evaluated in a *registered* environment (the root
/// environment of an `Env::eval` call, or a checking context's
/// environment): without it, a term DAG is evaluated as the tree it unfolds
/// to (exponential). The key is the addresses of the term and of the
/// environment vector; both are kept alive by the memo, so neither address
/// can be reused, and the environment — now shared — is never extended in
/// place (`venv_push_owned` copies a shared vector). Evaluation is a
/// function of the term, the environment and the mode, and a memo belongs
/// to one evaluator mode; speculative evaluators (which fold recursive
/// calls) never consult it. Only nodes evaluated directly in a registered
/// environment are memoized (not definition bodies under their own
/// environments), so the memo's size is bounded by the evaluated term.
#[derive(Default)]
pub(crate) struct EvalMemo {
    map: crate::util::FxMap<(usize, usize), V>,
    envs: crate::util::FxSet<usize>,
    keep_envs: Vec<VEnv>,
    keep_terms: Vec<Tm>,
}

impl EvalMemo {
    /// Register a root environment (its nodes will be memoized).
    pub(crate) fn register(&mut self, env: &VEnv) {
        if self.envs.insert(env_addr(env)) {
            self.keep_envs.push(env.clone());
        }
    }
}

fn env_addr(env: &VEnv) -> usize {
    Rc::as_ptr(&env.0) as *const () as usize
}

fn term_addr(t: &Tm) -> usize {
    Rc::as_ptr(t) as *const () as usize
}

/// Term nodes worth memoizing (compound, value-producing).
fn memo_node(t: &Tm) -> bool {
    matches!(
        &**t,
        Term::App { .. }
            | Term::Prim { .. }
            | Term::Ctor { .. }
            | Term::Pair { .. }
            | Term::Match { .. }
            | Term::Fst(_)
            | Term::Snd(_)
            | Term::Let { .. }
            | Term::Eq { .. }
            | Term::Refl { .. }
            | Term::Transport { .. }
            | Term::Ind { .. }
    )
}

/// The empty opaque set (transparent evaluation of every global).
pub(crate) fn no_globals(_: GlobalId) -> bool {
    false
}

impl<'e> Ev<'e> {
    pub fn new(env: &'e Env) -> Self {
        Ev { env, opaque: None, bv: false, transparent: false, spec: Vec::new(), folded: 0, folds: Vec::new(), memo: None }
    }

    /// Use (and share) `memo` for shared term nodes evaluated in `root`
    /// (see [`EvalMemo`]).
    pub fn with_memo(mut self, memo: Rc<std::cell::RefCell<EvalMemo>>, root: &VEnv) -> Self {
        memo.borrow_mut().register(root);
        self.memo = Some(memo);
        self
    }

    /// Use (and share) `memo` without registering an environment (roots are
    /// registered by [`Ev::inst_root`] / [`Ev::register`]).
    pub fn sharing(mut self, memo: Rc<std::cell::RefCell<EvalMemo>>) -> Self {
        self.memo = Some(memo);
        self
    }

    /// A fresh memo registered for `root`.
    pub fn memoized(self, root: &VEnv) -> Self {
        self.with_memo(Rc::new(std::cell::RefCell::new(EvalMemo::default())), root)
    }

    pub fn with_opaque(env: &'e Env, opaque: &'e dyn Fn(GlobalId) -> bool) -> Self {
        Ev { env, opaque: Some(opaque), bv: false, transparent: false, spec: Vec::new(), folded: 0, folds: Vec::new(), memo: None }
    }

    /// The fully transparent mode (`eval_opaque` with an empty set): no
    /// global is folded.
    pub fn transparent(env: &'e Env) -> Self {
        Ev { transparent: true, ..Ev::with_opaque(env, &no_globals) }
    }

    /// The `BvRefl` evaluation mode (DESIGN.md §9.3, §9.8; phase 3):
    /// transparent — opaque definitions unfold, no global is folded — and
    /// intrinsics unfold on symbolic data. Unfolding a definition is an
    /// identity, so this is sound; opacity only ever cost completeness, and
    /// `BvRefl` is the rule that proves hardware variants equal to portable
    /// functions whose loops make them opaque by default.
    pub fn bv(env: &'e Env) -> Self {
        Ev { bv: true, ..Ev::transparent(env) }
    }

    /// Does `g` stay folded in this mode?
    fn is_opaque(&self, g: GlobalId) -> bool {
        match self.opaque {
            Some(f) => f(g),
            None => self.env.defs.get(g.0 as usize).is_some_and(|d| d.opaque),
        }
    }

    fn bool_v(&self, b: bool) -> V {
        prim::bool_v(self.env.bool_id, b)
    }

    /// Evaluate `t` in `env` (whose length is the number of free variables of
    /// `t`); `depth` is the depth of the ambient context (for conversion and
    /// fresh variables).
    pub fn eval(&mut self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> R<V> {
        tick(b)?;
        if self.memo.is_some() && Rc::strong_count(t) > 1 && memo_node(t) {
            return self.eval_memo(env, depth, t, b);
        }
        self.eval_plain(env, depth, t, b)
    }

    /// [`Ev::eval`] of a shared node through the memo (if `env` is
    /// registered).
    #[inline(never)]
    fn eval_memo(&mut self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> R<V> {
        let m = self.memo.clone().expect("memo");
        let key = (term_addr(t), env_addr(env));
        {
            let mb = m.borrow();
            if !mb.envs.contains(&key.1) {
                drop(mb);
                return self.eval_plain(env, depth, t, b);
            }
            if let Some(v) = mb.map.get(&key) {
                return Ok(v.clone());
            }
        }
        let v = self.eval_plain(env, depth, t, b)?;
        let mut mb = m.borrow_mut();
        mb.map.insert(key, v.clone());
        mb.keep_terms.push(t.clone());
        Ok(v)
    }

    fn eval_plain(&mut self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> R<V> {
        if !matches!(&**t, Term::Let { .. } | Term::App { .. } | Term::Match { .. }) {
            return self.eval_node(env, depth, t, b);
        }
        self.eval_chain(env, depth, t, b)
    }

    /// Terms whose value is the value of another term (let bodies, match arms
    /// of a constructor scrutinee, β-reduction, unfolding of a global in
    /// result position) are evaluated iteratively, so tail recursion (e.g.
    /// loop helpers) runs in constant Rust stack.
    #[inline(never)]
    fn eval_chain(&mut self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> R<V> {
        let step = self.tail_step(env.clone(), depth, t, b)?;
        self.run(step, depth, b)
    }

    /// Run a step to completion iteratively (tail positions use no Rust
    /// stack).
    fn run(&mut self, mut step: Step, depth: Lvl, b: &mut Budget) -> R<V> {
        loop {
            step = match step {
                Step::Done(v) => return Ok(v),
                Step::Continue(env, t) => {
                    tick(b)?;
                    self.tail_step(env, depth, &t, b)?
                }
                Step::Apply(g, args) => {
                    tick(b)?;
                    self.policy_step(g, args, depth, b)?
                }
            }
        }
    }

    /// One tail step. The environment is owned, so a let or match arm
    /// extends it in place when nothing else refers to it.
    #[inline(never)]
    fn tail_step(&mut self, env: VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> R<Step> {
        match &**t {
            Term::Let { rel, val, body, .. } => {
                let e = self.entry(&env, depth, *rel, val, b)?;
                let reg = self.registered(&env);
                let env2 = venv_push_owned(env, e);
                self.derive(reg, &env2);
                Ok(Step::Continue(env2, body.clone()))
            }
            Term::App { .. } => self.app_step(&env, depth, t, b),
            Term::Match { scrut, arms, .. } => {
                let s = self.eval(&env, depth, scrut, b)?;
                if let Value::Ctor { ctor, args, .. } = &*s {
                    return Ok(match arms.get(*ctor as usize) {
                        Some(arm) => {
                            let reg = self.registered(&env);
                            let env2 = venv_extend_owned(env, args.iter().map(arg_entry));
                            self.derive(reg, &env2);
                            Step::Continue(env2, arm.body.clone())
                        }
                        None => Step::Done(garbage()),
                    });
                }
                Ok(Step::Done(self.stuck_match(&env, depth, t, &s, b)?))
            }
            _ => Ok(Step::Done(self.eval_node(&env, depth, t, b)?)),
        }
    }

    /// An application spine; the last application is performed in tail
    /// position.
    #[inline(never)]
    fn app_step(&mut self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> R<Step> {
        let mut spine: Vec<(Rel, &Tm)> = Vec::new();
        let mut head = t;
        while let Term::App { rel, fun, arg } = &**head {
            spine.push((*rel, arg));
            head = fun;
        }
        spine.reverse();
        if let (Term::Lam { body, .. }, 1) = (&**head, spine.len()) {
            let e = self.entry(env, depth, spine[0].0, spine[0].1, b)?;
            let env2 = venv_push(env, e);
            self.derive(self.registered(env), &env2);
            return Ok(Step::Continue(env2, body.clone()));
        }
        let mut f = self.eval(env, depth, head, b)?;
        let mut args = Vec::with_capacity(spine.len());
        for (rel, a) in &spine {
            args.push(self.arg(env, depth, *rel, a, b)?);
        }
        let last = args.pop().expect("nonempty spine");
        for a in args {
            f = self.apply(&f, a, depth, b)?;
        }
        self.apply_step(&f, last, depth, b)
    }

    /// [`Ev::apply`] in tail position.
    fn apply_step(&mut self, f: &V, a: Arg, depth: Lvl, b: &mut Budget) -> R<Step> {
        match &**f {
            Value::Lam { body, .. } => Ok(Step::Continue(venv_push(&body.env, arg_entry(&a)), body.body.clone())),
            Value::Neu(n) => {
                if let Head::Global { def, args } = &n.head
                    && n.spine.is_empty()
                    && (args.len() as u32) + 1 == self.arity_of(*def)
                {
                    let mut args = args.clone();
                    args.push(a);
                    return self.policy_step(*def, args, depth, b);
                }
                Ok(Step::Done(self.apply(f, a, depth, b)?))
            }
            _ => Ok(Step::Done(garbage())),
        }
    }

    /// Evaluate an argument of the given relevance into an environment entry.
    fn entry(&mut self, env: &VEnv, depth: Lvl, rel: Rel, t: &Tm, b: &mut Budget) -> R<EnvEntry> {
        Ok(match rel {
            Rel::Rel => EnvEntry::Rel(self.eval(env, depth, t, b)?),
            Rel::Irr => EnvEntry::Irr(Closure { env: env.clone(), body: t.clone() }),
        })
    }

    fn arg(&mut self, env: &VEnv, depth: Lvl, rel: Rel, t: &Tm, b: &mut Budget) -> R<Arg> {
        Ok(match rel {
            Rel::Rel => Arg::Rel(self.eval(env, depth, t, b)?),
            Rel::Irr => Arg::Irr(Closure { env: env.clone(), body: t.clone() }),
        })
    }

    /// Dispatch on the term constructor. Every non-trivial case lives in its
    /// own (non-inlined) method so that this frame stays small: evaluation
    /// recursion depth is bounded by the stack (debug builds keep every local
    /// of a large `match` in one frame).
    fn eval_node(&mut self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> R<V> {
        match &**t {
            Term::Var(i) => self.ev_var(env, depth, *i, b),
            Term::App { rel, fun, arg } => self.ev_app(env, depth, *rel, fun, arg, b),
            Term::Match { .. } => self.ev_match(env, depth, t, b),
            Term::Prim { op, args, proofs } => self.ev_prim(env, depth, *op, args, proofs, b),
            Term::Ctor { ind, ctor, params, args } => self.ev_ctor(env, depth, *ind, *ctor, params, args, b),
            Term::Global(g) => self.global(*g, depth, b),
            _ => self.ev_rest(env, depth, t, b),
        }
    }

    #[inline(never)]
    fn ev_rest(&mut self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> R<V> {
        match &**t {
            Term::Sort(s) => Ok(Rc::new(Value::Sort(*s))),
            Term::IntTy(w) => Ok(Rc::new(Value::IntTy(*w))),
            Term::Lit { w, n } => {
                if *w == Width::Int {
                    prim::check_int(n)?;
                }
                Ok(Rc::new(Value::Lit { w: *w, n: n.clone() }))
            }
            Term::Pi { .. } | Term::Lam { .. } | Term::Sigma { .. } => self.ev_binder(env, depth, t, b),
            Term::Pair { ty, fst, snd } => self.ev_pair(env, depth, ty, fst, snd, b),
            Term::Fst(p) => {
                let p = self.eval(env, depth, p, b)?;
                Ok(self.fst(&p))
            }
            Term::Snd(p) => {
                let p = self.eval(env, depth, p, b)?;
                self.snd(&p, depth, b)
            }
            Term::Eq { .. } | Term::Refl { .. } | Term::BvRefl { .. } | Term::Linarith { .. } | Term::Delta { .. } => {
                self.ev_eq(env, depth, t, b)
            }
            Term::Transport { .. } => self.ev_transport(env, depth, t, b),
            Term::Ind { ind, params } => {
                let params = self.eval_all(env, depth, params, b)?;
                Ok(Rc::new(Value::Ind { ind: *ind, params }))
            }
            Term::Rec { args, .. } => self.ev_rec(env, depth, args, b),
            Term::Unfold { val, .. } => self.eval(env, depth, val, b),
            Term::Absurd { ty, .. } => {
                let ty = self.eval(env, depth, ty, b)?;
                Ok(neu(Head::Absurd { ty }, Vec::new()))
            }
            Term::Axiom { ax, args } => self.ev_axiom(env, depth, *ax, args, b),
            Term::Erased => Ok(garbage()),
            Term::Var(_)
            | Term::App { .. }
            | Term::Match { .. }
            | Term::Prim { .. }
            | Term::Ctor { .. }
            | Term::Global(_)
            | Term::Let { .. } => self.eval(env, depth, t, b),
        }
    }

    fn eval_all(&mut self, env: &VEnv, depth: Lvl, ts: &[Tm], b: &mut Budget) -> R<Vec<V>> {
        let mut out = Vec::with_capacity(ts.len());
        for t in ts {
            out.push(self.eval(env, depth, t, b)?);
        }
        Ok(out)
    }

    #[inline(never)]
    fn ev_var(&mut self, env: &VEnv, depth: Lvl, i: Idx, b: &mut Budget) -> R<V> {
        match venv_get(env, i) {
            Some(EnvEntry::Rel(v)) => Ok(v.clone()),
            // Reachable only inside irrelevant positions (a resurrected
            // variable, whose value the checker may need for the types of a
            // proof) or for ill-typed input: relevant code never reads an
            // irrelevant variable. Forcing the closure is harmless.
            Some(EnvEntry::Irr(c)) => {
                let c = c.clone();
                self.eval(&c.env, depth, &c.body, b)
            }
            None => Ok(garbage()),
        }
    }

    #[inline(never)]
    fn ev_binder(&mut self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> R<V> {
        let clo = |body: &Tm| Closure { env: env.clone(), body: body.clone() };
        Ok(match &**t {
            Term::Pi { name, rel, dom, cod } => {
                Rc::new(Value::Pi { name: name.clone(), rel: *rel, dom: self.eval(env, depth, dom, b)?, cod: clo(cod) })
            }
            Term::Lam { name, rel, dom, body } => {
                Rc::new(Value::Lam { name: name.clone(), rel: *rel, dom: self.eval(env, depth, dom, b)?, body: clo(body) })
            }
            Term::Sigma { name, snd_rel, fst, snd } => {
                Rc::new(Value::Sigma { name: name.clone(), snd_rel: *snd_rel, fst: self.eval(env, depth, fst, b)?, snd: clo(snd) })
            }
            _ => garbage(),
        })
    }

    #[inline(never)]
    fn ev_app(&mut self, env: &VEnv, depth: Lvl, rel: Rel, fun: &Tm, arg: &Tm, b: &mut Budget) -> R<V> {
        let f = self.eval(env, depth, fun, b)?;
        let a = self.arg(env, depth, rel, arg, b)?;
        self.apply(&f, a, depth, b)
    }

    #[inline(never)]
    fn ev_pair(&mut self, env: &VEnv, depth: Lvl, ty: &Tm, fst: &Tm, snd: &Tm, b: &mut Budget) -> R<V> {
        let rel = self.pair_rel(env, depth, ty, b)?;
        let f = self.eval(env, depth, fst, b)?;
        let s = self.arg(env, depth, rel, snd, b)?;
        Ok(Rc::new(Value::Pair { fst: f, snd: s }))
    }

    /// `Eq`, and the proof terms whose value is `refl` (or an absurd neutral).
    #[inline(never)]
    fn ev_eq(&mut self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> R<V> {
        Ok(match &**t {
            Term::Eq { ty, lhs, rhs } => Rc::new(Value::Eq {
                ty: self.eval(env, depth, ty, b)?,
                lhs: self.eval(env, depth, lhs, b)?,
                rhs: self.eval(env, depth, rhs, b)?,
            }),
            Term::Refl { ty, val } | Term::BvRefl { ty, lhs: val, .. } => {
                Rc::new(Value::Refl { ty: self.eval(env, depth, ty, b)?, val: self.eval(env, depth, val, b)? })
            }
            Term::Linarith { goal, .. } => {
                let g = self.eval(env, depth, goal, b)?;
                match &*g {
                    Value::Eq { ty, lhs, .. } => Rc::new(Value::Refl { ty: ty.clone(), val: lhs.clone() }),
                    _ => neu(Head::Absurd { ty: g.clone() }, Vec::new()),
                }
            }
            Term::Delta { def, args } => {
                let genv = self.env;
                let Some(d) = genv.defs.get(def.0 as usize) else { return Ok(garbage()) };
                let vs = self.telescope_args(env, depth, &d.param_rels, args, b)?;
                let r = self.eval(&VEnv(Rc::new(vs.iter().map(arg_entry).collect())), depth, &d.res_ty, b)?;
                let val = self.global_app(*def, vs, depth, b)?;
                Rc::new(Value::Refl { ty: r, val })
            }
            _ => garbage(),
        })
    }

    #[inline(never)]
    fn ev_transport(&mut self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> R<V> {
        let Term::Transport { ty, lhs, rhs, motive, val, .. } = &**t else { return Ok(garbage()) };
        let tv = self.eval(env, depth, ty, b)?;
        let lv = self.eval(env, depth, lhs, b)?;
        let rv = self.eval(env, depth, rhs, b)?;
        let vv = self.eval(env, depth, val, b)?;
        if crate::conv::Conv::like(self).conv(depth, &lv, &rv, b)? {
            Ok(vv)
        } else {
            let motive = Closure { env: env.clone(), body: motive.clone() };
            Ok(neu(Head::Transport { ty: tv, lhs: lv, rhs: rv, motive, val: vv }, Vec::new()))
        }
    }

    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn ev_ctor(&mut self, env: &VEnv, depth: Lvl, ind: IndId, ctor: u32, params: &[Tm], args: &[Tm], b: &mut Budget) -> R<V> {
        let params = self.eval_all(env, depth, params, b)?;
        let args = self.ctor_args(env, depth, ind, ctor, args, b)?;
        Ok(Rc::new(Value::Ctor { ind, ctor, params, args }))
    }

    fn ctor_args(&mut self, env: &VEnv, depth: Lvl, ind: IndId, ctor: u32, args: &[Tm], b: &mut Budget) -> R<Vec<Arg>> {
        let genv = self.env;
        let fields = genv.inds.get(ind.0 as usize).and_then(|i| i.ctors.get(ctor as usize)).map(|c| &c.fields);
        let mut vs = Vec::with_capacity(args.len());
        for (i, a) in args.iter().enumerate() {
            let rel = fields.and_then(|f| f.get(i)).map(|f| f.1).unwrap_or(Rel::Rel);
            vs.push(self.arg(env, depth, rel, a, b)?);
        }
        Ok(vs)
    }

    #[inline(never)]
    fn ev_match(&mut self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> R<V> {
        let Term::Match { scrut, arms, .. } = &**t else { return Ok(garbage()) };
        let s = self.eval(env, depth, scrut, b)?;
        if let Value::Ctor { ctor, args, .. } = &*s {
            return match arms.get(*ctor as usize) {
                Some(arm) => {
                    let env2 = venv_extend(env, args.iter().map(arg_entry));
                    self.derive(self.registered(env), &env2);
                    self.eval(&env2, depth, &arm.body, b)
                }
                None => Ok(garbage()),
            };
        }
        self.stuck_match(env, depth, t, &s, b)
    }

    /// A match whose scrutinee is not a constructor.
    #[inline(never)]
    fn stuck_match(&mut self, env: &VEnv, depth: Lvl, t: &Tm, s: &V, b: &mut Budget) -> R<V> {
        let Term::Match { ind, params, motive, arms, .. } = &**t else { return Ok(garbage()) };
        match &**s {
            Value::Neu(n) => {
                let params = self.eval_all(env, depth, params, b)?;
                let clo = |body: &Tm| Closure { env: env.clone(), body: body.clone() };
                let arms = arms.iter().map(|a| clo(&a.body)).collect();
                Ok(push_elim(n, Elim::Match { ind: *ind, params, motive: clo(motive), arms }))
            }
            _ => Ok(garbage()),
        }
    }

    #[inline(never)]
    fn ev_prim(&mut self, env: &VEnv, depth: Lvl, op: PrimOp, args: &[Tm], proofs: &[Tm], b: &mut Budget) -> R<V> {
        let args = self.eval_all(env, depth, args, b)?;
        let proofs = proofs.iter().map(|p| Closure { env: env.clone(), body: p.clone() }).collect();
        self.prim(op, args, proofs, depth, b)
    }

    #[inline(never)]
    fn ev_rec(&mut self, env: &VEnv, depth: Lvl, args: &[Tm], b: &mut Budget) -> R<V> {
        let Some(p) = &self.env.pending else { return Ok(garbage()) };
        let (id, rels) = (p.id, p.param_rels.clone());
        let vs = self.telescope_args(env, depth, &rels, args, b)?;
        Ok(neu(Head::Global { def: id, args: vs }, Vec::new()))
    }

    #[inline(never)]
    fn ev_axiom(&mut self, env: &VEnv, depth: Lvl, ax: crate::term::AxiomId, args: &[Tm], b: &mut Budget) -> R<V> {
        let rels = crate::axioms::axiom_param_rels(ax);
        let vs = self.telescope_args(env, depth, &rels, args, b)?;
        Ok(neu(Head::Axiom { ax, args: vs }, Vec::new()))
    }

    /// Evaluate arguments against a list of parameter relevances.
    fn telescope_args(&mut self, env: &VEnv, depth: Lvl, rels: &[Rel], args: &[Tm], b: &mut Budget) -> R<Vec<Arg>> {
        let mut vs = Vec::with_capacity(args.len());
        for (i, a) in args.iter().enumerate() {
            let rel = rels.get(i).copied().unwrap_or(Rel::Rel);
            vs.push(self.arg(env, depth, rel, a, b)?);
        }
        Ok(vs)
    }

    /// Relevance of the second component of a pair of type `ty`.
    fn pair_rel(&mut self, env: &VEnv, depth: Lvl, ty: &Tm, b: &mut Budget) -> R<Rel> {
        if let Term::Sigma { snd_rel, .. } = &**ty {
            return Ok(*snd_rel);
        }
        let v = self.eval(env, depth, ty, b)?;
        Ok(match &*v {
            Value::Sigma { snd_rel, .. } => *snd_rel,
            _ => Rel::Rel,
        })
    }

    /// Instantiate a closure with one more entry.
    pub fn inst(&mut self, c: &Closure, e: EnvEntry, depth: Lvl, b: &mut Budget) -> R<V> {
        self.eval(&venv_push(&c.env, e), depth, &c.body, b)
    }

    /// Instantiate a closure with several entries (match arms).
    pub fn inst_n(&mut self, c: &Closure, es: Vec<EnvEntry>, depth: Lvl, b: &mut Budget) -> R<V> {
        self.eval(&venv_extend(&c.env, es), depth, &c.body, b)
    }

    /// [`Ev::inst`] for a root instantiation (conversion, quoting, checking
    /// under a binder): the new environment is registered in the memo, so a
    /// shared closure body is evaluated as a DAG.
    pub fn inst_root(&mut self, c: &Closure, e: EnvEntry, depth: Lvl, b: &mut Budget) -> R<V> {
        let env = venv_push(&c.env, e);
        self.register(&env);
        self.eval(&env, depth, &c.body, b)
    }

    /// [`Ev::inst_n`] for a root instantiation (see [`Ev::inst_root`]).
    pub fn inst_n_root(&mut self, c: &Closure, es: Vec<EnvEntry>, depth: Lvl, b: &mut Budget) -> R<V> {
        let env = venv_extend(&c.env, es);
        self.register(&env);
        self.eval(&env, depth, &c.body, b)
    }

    /// Register `env` in the memo (if any).
    pub fn register(&self, env: &VEnv) {
        if let Some(m) = &self.memo {
            m.borrow_mut().register(env);
        }
    }

    /// Is `env` registered in the memo?
    fn registered(&self, env: &VEnv) -> bool {
        self.memo.as_ref().is_some_and(|m| m.borrow().envs.contains(&env_addr(env)))
    }

    /// Register `child` (an extension of a registered environment by a let,
    /// a match arm or an immediate β-redex of the evaluated term) if its
    /// parent was registered. These extensions happen while evaluating the
    /// registered term itself (not definition bodies, which get fresh
    /// environments), so their number is bounded by the term.
    fn derive(&self, parent_registered: bool, child: &VEnv) {
        if parent_registered {
            self.register(child);
        }
    }

    /// Apply a value to an argument.
    pub fn apply(&mut self, f: &V, a: Arg, depth: Lvl, b: &mut Budget) -> R<V> {
        match &**f {
            Value::Lam { body, .. } => self.inst(body, arg_entry(&a), depth, b),
            Value::Neu(n) => {
                if let Head::Global { def, args } = &n.head
                    && n.spine.is_empty()
                    && (args.len() as u32) < self.arity_of(*def)
                {
                    let mut args = args.clone();
                    args.push(a);
                    return self.global_app(*def, args, depth, b);
                }
                Ok(push_elim(n, Elim::App(a)))
            }
            _ => Ok(garbage()),
        }
    }

    pub fn fst(&mut self, p: &V) -> V {
        match &**p {
            Value::Pair { fst, .. } => fst.clone(),
            Value::Neu(n) => push_elim(n, Elim::Fst),
            _ => garbage(),
        }
    }

    pub fn snd(&mut self, p: &V, depth: Lvl, b: &mut Budget) -> R<V> {
        Ok(match &**p {
            Value::Pair { snd: Arg::Rel(v), .. } => v.clone(),
            // `snd` of an Irr Σ only occurs in irrelevant positions, whose
            // values relevant code never reads (the checker may evaluate
            // them for the types of a proof); forcing is harmless.
            Value::Pair { snd: Arg::Irr(c), .. } => {
                let c = c.clone();
                self.eval(&c.env, depth, &c.body, b)?
            }
            Value::Neu(n) => push_elim(n, Elim::Snd),
            _ => garbage(),
        })
    }

    fn arity_of(&self, g: GlobalId) -> u32 {
        if let Some(d) = self.env.defs.get(g.0 as usize) {
            return d.arity;
        }
        match &self.env.pending {
            Some(p) if p.id == g => p.arity,
            _ => 0,
        }
    }

    /// `Term::Global(g)`.
    fn global(&mut self, g: GlobalId, depth: Lvl, b: &mut Budget) -> R<V> {
        let env = self.env;
        let Some(d) = env.defs.get(g.0 as usize) else {
            return Ok(neu(Head::Global { def: g, args: Vec::new() }, Vec::new()));
        };
        if self.is_opaque(g) || d.is_recursive() || d.kind == DefKind::Intrinsic {
            return if d.arity == 0 {
                self.policy(g, Vec::new(), depth, b)
            } else {
                Ok(neu(Head::Global { def: g, args: Vec::new() }, Vec::new()))
            };
        }
        self.def_value(d, b)
    }

    /// The (closed) value of a non-recursive definition's body; cached for the
    /// default evaluation mode.
    fn def_value(&mut self, d: &'e DefInfo, b: &mut Budget) -> R<V> {
        // One cache per mode that has a fixed opacity (default and `BvRefl`);
        // the optimizer's transparent mode depends on its opaque set.
        let cache = match (self.opaque, self.bv) {
            (None, false) => Some(&d.cached),
            (Some(_), false) if self.transparent => Some(&d.cached_transparent),
            (Some(_), true) if self.transparent => Some(&d.cached_bv),
            _ => None,
        };
        if let Some(v) = cache.and_then(|c| c.get()) {
            return Ok(v.clone());
        }
        let v = self.eval(&VEnv::default(), Lvl(0), &d.body, b)?;
        if let Some(c) = cache
            && self.spec.is_empty()
        {
            let _ = c.set(v.clone());
        }
        Ok(v)
    }

    /// A global applied to some arguments (unfolding attempted once `arity`
    /// arguments are present).
    fn global_app(&mut self, g: GlobalId, args: Vec<Arg>, depth: Lvl, b: &mut Budget) -> R<V> {
        if (args.len() as u32) < self.arity_of(g) {
            return Ok(neu(Head::Global { def: g, args }, Vec::new()));
        }
        self.policy(g, args, depth, b)
    }

    /// Evaluate the body of `d` applied to exactly its `arity` arguments.
    /// A body that is a term DAG (`DefInfo::shared`) is evaluated with a
    /// memo scoped to this unfolding, so its shared nodes are evaluated once.
    pub(crate) fn unfold(&mut self, d: &DefInfo, args: &[Arg], depth: Lvl, b: &mut Budget) -> R<V> {
        let env = VEnv(Rc::new(args.iter().map(arg_entry).collect()));
        if d.shared {
            return self.eval_scoped(&env, depth, &d.inner, b);
        }
        self.eval(&env, depth, &d.inner, b)
    }

    /// Evaluate `t` in `env` with a fresh memo registered for `env` (dropped
    /// afterwards, so nothing is retained beyond this evaluation).
    fn eval_scoped(&mut self, env: &VEnv, depth: Lvl, t: &Tm, b: &mut Budget) -> R<V> {
        let saved = self.memo.replace(Rc::new(std::cell::RefCell::new(EvalMemo::default())));
        self.register(env);
        let r = self.eval(env, depth, t, b);
        self.memo = saved;
        r
    }

    /// The step that evaluates the body of `d` on `args`: a tail step, or
    /// (for a shared body, see [`Ev::unfold`]) the value.
    fn body_step(&mut self, d: &DefInfo, args: &[Arg], depth: Lvl, b: &mut Budget) -> R<Step> {
        if d.shared {
            return Ok(Step::Done(self.unfold(d, args, depth, b)?));
        }
        Ok(Step::Continue(VEnv(Rc::new(args.iter().map(arg_entry).collect())), d.inner.clone()))
    }

    /// `g` applied to exactly its `arity` arguments under this evaluator's
    /// mode (in the `BvRefl` mode an intrinsic unfolds on symbolic data).
    pub fn apply_global_full(&mut self, g: GlobalId, args: Vec<Arg>, depth: Lvl, b: &mut Budget) -> R<V> {
        self.policy(g, args, depth, b)
    }

    /// The §5.6 unfolding policy for `g` applied to exactly `arity` arguments.
    fn policy(&mut self, g: GlobalId, args: Vec<Arg>, depth: Lvl, b: &mut Budget) -> R<V> {
        let step = self.policy_step(g, args, depth, b)?;
        self.run(step, depth, b)
    }

    /// The unfolding policy; an unfolding is returned as the body to evaluate.
    #[inline(never)]
    fn policy_step(&mut self, g: GlobalId, args: Vec<Arg>, depth: Lvl, b: &mut Budget) -> R<Step> {
        let env = self.env;
        let neutral = |args: Vec<Arg>| Step::Done(neu(Head::Global { def: g, args }, Vec::new()));
        if self.is_opaque(g) {
            return Ok(neutral(args));
        }
        let Some(d) = env.defs.get(g.0 as usize) else { return Ok(neutral(args)) };
        if env.known.index == Some(g)
            && let Some(v) = self.index_simp(&args, depth, b)?
        {
            return Ok(Step::Done(v));
        }
        if let Some(w) = env.known.le_bytes_width(g)
            && let Some(v) = self.le_bytes_simp(w, &args, depth, b)?
        {
            return Ok(Step::Done(v));
        }
        if d.kind == DefKind::Intrinsic {
            let closed = self.bv
                || args.iter().all(|a| match a {
                    Arg::Rel(v) => is_closed(v),
                    Arg::Irr(_) => true,
                });
            return if closed { self.body_step(d, &args, depth, b) } else { Ok(neutral(args)) };
        }
        if !d.is_recursive() {
            return self.body_step(d, &args, depth, b);
        }
        if self.spec.contains(&g) {
            self.folded += 1;
            let v = neu(Head::Global { def: g, args }, Vec::new());
            self.folds.push(v.clone());
            return Ok(Step::Done(v));
        }
        self.speculate(g, d, args, depth, b)
    }

    /// The speculative unfolding test of §5.6 for a recursive global.
    #[inline(never)]
    fn speculate(&mut self, g: GlobalId, d: &'e DefInfo, args: Vec<Arg>, depth: Lvl, b: &mut Budget) -> R<Step> {
        let env = self.env;
        let neutral = |args: Vec<Arg>| Step::Done(neu(Head::Global { def: g, args }, Vec::new()));
        let limit = b.steps.min(SPEC_LIMIT);
        let mut sub = Budget { steps: limit };
        let mut stack = self.spec.clone();
        stack.push(g);
        let mut spec = Ev {
            env,
            opaque: self.opaque,
            bv: self.bv,
            transparent: self.transparent,
            spec: stack,
            folded: 0,
            folds: Vec::new(),
            memo: None,
        };
        let r = spec.unfold(d, &args, depth, &mut sub);
        b.steps -= limit - sub.steps;
        let (folded, folds) = (spec.folded, std::mem::take(&mut spec.folds));
        drop(spec);
        match r {
            // Only the sub-budget ran out (not the caller's budget, not the
            // stack). In the transparent mode (the optimizer's and the
            // reference evaluator's), an application to closed arguments with
            // a ground recursion argument is a terminating closed computation
            // that is merely long: evaluate its body with the caller's budget
            // (an exhausted caller budget is an error, as for any
            // evaluation). Otherwise the application stays neutral, which is
            // always sound.
            Err(EvalError::OutOfFuel) if sub.steps == 0 && limit == SPEC_LIMIT && b.steps > 0 => {
                if self.opaque.is_some() && self.spec.is_empty() && closed_args(&args) && self.ground_recursion(d, &args, depth, b)? {
                    let v2 = self.unfold(d, &args, depth, b)?;
                    return Ok(if stuck_at_head(&v2) { neutral(args) } else { Step::Done(v2) });
                }
                Ok(neutral(args))
            }
            Err(e) => Err(e),
            // Stuck only because a folded recursive call is inspected (e.g.
            // `match rec(t) with ..`), and the recursion argument is ground
            // (see `ground_recursion`): the recursion terminates (the
            // definition passed its termination check), so evaluate the body
            // with the real policy — its recursive calls are on ground
            // arguments again and compute (§5.6 refinement, phase 3). If the
            // result is still stuck (on symbolic data or an opaque call) the
            // application stays folded, as before.
            Ok(v) if stuck_at_head(&v) && folded > 0 && blocked_by_fold(&v, &folds) && self.ground_recursion(d, &args, depth, b)? => {
                drop(v);
                drop(folds);
                let v2 = self.unfold(d, &args, depth, b)?;
                Ok(if stuck_at_head(&v2) { neutral(args) } else { Step::Done(v2) })
            }
            Ok(v) if stuck_at_head(&v) => Ok(neutral(args)),
            // Nothing was folded: the speculative value is the real one.
            Ok(v) if folded == 0 => Ok(Step::Done(v)),
            Ok(v) => match self.resume(g, v, folds, folded, depth, b)? {
                Some(step) => Ok(step),
                None => self.body_step(d, &args, depth, b),
            },
        }
    }

    /// Is the recursion argument of `d` applied to `args` ground, so that
    /// unfolding the recursion to the bottom terminates? Structural
    /// recursion: the structural argument is a closed constructor spine
    /// (every recursive field, transitively, is a constructor; the other
    /// fields may be symbolic). Measure recursion: the measure evaluates to
    /// a literal (every recursive call strictly decreases it, by the checked
    /// decrease proofs). A heuristic for completeness only: unfolding is
    /// always sound, and a wrong guess merely costs evaluation (or ends in
    /// `OutOfFuel`, never in a wrong value).
    fn ground_recursion(&mut self, d: &DefInfo, args: &[Arg], depth: Lvl, b: &mut Budget) -> R<bool> {
        match &d.recursion {
            crate::term::Recursion::None => Ok(false),
            crate::term::Recursion::Structural { param } => Ok(match args.get(*param as usize) {
                Some(Arg::Rel(v)) => self.closed_spine(v),
                _ => false,
            }),
            crate::term::Recursion::Measure { measure } => {
                let env = VEnv(Rc::new(args.iter().map(arg_entry).collect()));
                let m = self.eval(&env, depth, measure, b)?;
                Ok(prim::as_lit(&m).is_some())
            }
        }
    }

    /// `v` is a constructor whose recursive fields are, transitively,
    /// constructors (a finite spine; other fields arbitrary).
    fn closed_spine(&self, v: &V) -> bool {
        let mut stack = vec![v.clone()];
        let mut fuel = 1usize << 20;
        while let Some(v) = stack.pop() {
            if fuel == 0 {
                return false;
            }
            fuel -= 1;
            let Value::Ctor { ind, ctor, args, .. } = &*v else { return false };
            let Some(flags) = self.env.inds.get(ind.0 as usize).and_then(|i| i.rec_fields.get(*ctor as usize)) else { return false };
            for (a, is_rec) in args.iter().zip(flags) {
                if *is_rec {
                    match a {
                        Arg::Rel(x) => stack.push(x.clone()),
                        Arg::Irr(_) => return false,
                    }
                }
            }
        }
        true
    }

    /// Reuse a successful speculation of `g` instead of re-evaluating its
    /// body (a pure optimization; `None` falls back to re-evaluation). The
    /// real value of the body is the speculative value `v` with every folded
    /// application `g args'` replaced by `g args'` under the real policy. That
    /// substitution is performed when the folded applications (all of `g`
    /// itself) are referenced **only** from the top of `v` — `v` is the
    /// folded application itself (tail recursion), or a constructor/pair
    /// with folded applications as direct relevant fields (e.g. `Cons(h,
    /// rec(..))`) — which reference counts prove (the recorded list holds one
    /// reference; any other holder would be an occurrence we do not see).
    fn resume(&mut self, g: GlobalId, v: V, folds: Vec<V>, folded: u64, depth: Lvl, b: &mut Budget) -> R<Option<Step>> {
        if folds.len() as u64 != folded
            || folds.iter().any(|f| !matches!(&**f, Value::Neu(Neutral { head: Head::Global { def, .. }, .. }) if *def == g))
        {
            return Ok(None);
        }
        let args_of = |f: &V| match &**f {
            Value::Neu(Neutral { head: Head::Global { args, .. }, .. }) => args.clone(),
            _ => unreachable!("checked above"),
        };
        // Tail recursion: the body's value is the recursive call itself.
        if folds.len() == 1 && Rc::ptr_eq(&v, &folds[0]) && Rc::strong_count(&v) == 2 {
            return Ok(Some(Step::Apply(g, args_of(&folds[0]))));
        }
        // Folded calls as direct fields of a constructor or pair.
        let direct = |f: &V| -> usize {
            match &*v {
                Value::Ctor { args, .. } => args.iter().filter(|a| matches!(a, Arg::Rel(x) if Rc::ptr_eq(x, f))).count(),
                Value::Pair { fst, snd } => Rc::ptr_eq(fst, f) as usize + matches!(snd, Arg::Rel(x) if Rc::ptr_eq(x, f)) as usize,
                _ => 0,
            }
        };
        if Rc::strong_count(&v) != 1 || folds.iter().any(|f| direct(f) == 0 || Rc::strong_count(f) != 1 + direct(f)) {
            return Ok(None);
        }
        let mut real: Vec<(V, V)> = Vec::with_capacity(folds.len());
        for f in &folds {
            let r = self.policy(g, args_of(f), depth, b)?;
            real.push((f.clone(), r));
        }
        let swap = |x: &V| real.iter().find(|(f, _)| Rc::ptr_eq(f, x)).map(|(_, r)| r.clone()).unwrap_or_else(|| x.clone());
        let out = match &*v {
            Value::Ctor { ind, ctor, params, args } => Rc::new(Value::Ctor {
                ind: *ind,
                ctor: *ctor,
                params: params.clone(),
                args: args
                    .iter()
                    .map(|a| match a {
                        Arg::Rel(x) => Arg::Rel(swap(x)),
                        Arg::Irr(c) => Arg::Irr(c.clone()),
                    })
                    .collect(),
            }),
            Value::Pair { fst, snd } => Rc::new(Value::Pair {
                fst: swap(fst),
                snd: match snd {
                    Arg::Rel(x) => Arg::Rel(swap(x)),
                    Arg::Irr(c) => Arg::Irr(c.clone()),
                },
            }),
            _ => return Ok(None),
        };
        Ok(Some(Step::Done(out)))
    }

    /// `index(T, take(T, l, n), i) → index(T, l, i)` for literals `i < n`, and
    /// `index(T, drop(T, l, a), i) → index(T, l, a + i)` for literals `a ≥ 0`,
    /// `i` (true for every well-typed occurrence, whose proofs guarantee
    /// `0 ≤ i < len(take/drop(..))`).
    fn index_simp(&mut self, args: &[Arg], depth: Lvl, b: &mut Budget) -> R<Option<V>> {
        let env = self.env;
        let known = &env.known;
        let (Some(Arg::Rel(l)), Some(Arg::Rel(i))) = (args.get(1), args.get(2)) else { return Ok(None) };
        let Some(i) = prim::as_lit(i) else { return Ok(None) };
        // `index(T, Cons(x0, Cons(x1, ..)), i)` is `x_max(i, 0)` when the
        // constructor spine is that long: exactly what unfolding the
        // definition computes (`if i ≤ 0 then x else index(t, i − 1)`),
        // without one speculative unfolding per element.
        let k = if i.is_negative() { 0 } else { i.to_usize().unwrap_or(usize::MAX) };
        let mut cur = l;
        let mut steps = 0usize;
        loop {
            match &**cur {
                Value::Ctor { ind, ctor: 1, args: cell, .. } if Some(*ind) == known.list && cell.len() == 2 => {
                    let (Arg::Rel(h), Arg::Rel(t)) = (&cell[0], &cell[1]) else { break };
                    if steps == k {
                        return Ok(Some(h.clone()));
                    }
                    tick(b)?;
                    steps += 1;
                    cur = t;
                }
                _ => break,
            }
        }
        let Value::Neu(Neutral { head: Head::Global { def, args: inner }, spine }) = &**l else { return Ok(None) };
        if !spine.is_empty() || inner.len() != 3 {
            return Ok(None);
        }
        let (Arg::Rel(l2), Arg::Rel(n)) = (&inner[1], &inner[2]) else { return Ok(None) };
        let Some(n) = prim::as_lit(n) else { return Ok(None) };
        let new_i = if Some(*def) == known.take && i < n && !i.is_negative() {
            i.clone()
        } else if Some(*def) == known.drop && !n.is_negative() && !i.is_negative() {
            n + i
        } else {
            return Ok(None);
        };
        let mut args2 = args.to_vec();
        args2[1] = Arg::Rel(l2.clone());
        args2[2] = Arg::Rel(prim::lit_v(Width::Int, new_i));
        let g = known.index.expect("index");
        self.policy(g, args2, depth, b).map(Some)
    }

    /// The elements of a pair whose first component is a concrete list.
    fn array_elems(&self, v: &V) -> Option<Vec<V>> {
        let list = self.env.known.list?;
        let Value::Pair { fst, .. } = &**v else { return None };
        let mut out = Vec::new();
        let mut cur = fst.clone();
        loop {
            let next = match &*cur {
                Value::Ctor { ind, ctor: 0, .. } if *ind == list => return Some(out),
                Value::Ctor { ind, ctor: 1, args, .. } if *ind == list && args.len() == 2 => {
                    let (Arg::Rel(h), Arg::Rel(t)) = (&args[0], &args[1]) else { return None };
                    out.push(h.clone());
                    t.clone()
                }
                _ => return None,
            };
            cur = next;
        }
    }

    /// `from_le_bytes_w([cast_u8(x), cast_u8(x >> 8), ..]) → x`.
    fn le_bytes_simp(&mut self, w: Width, args: &[Arg], depth: Lvl, b: &mut Budget) -> R<Option<V>> {
        let Some(Arg::Rel(arr)) = args.first() else { return Ok(None) };
        let Some(elems) = self.array_elems(arr) else { return Ok(None) };
        let nbytes = prim::bits(w) / 8;
        if elems.len() != nbytes as usize {
            return Ok(None);
        }
        let mut x: Option<V> = None;
        for (k, e) in elems.iter().enumerate() {
            let Some((PrimOp::Cast { from, to: Width::U8 }, inner)) = prim::as_prim(e) else { return Ok(None) };
            if from != w {
                return Ok(None);
            }
            let src = if k == 0 {
                inner[0].clone()
            } else {
                match prim::as_prim(&inner[0]) {
                    Some((PrimOp::WShr(w2) | PrimOp::Shr(w2), sh)) if w2 == w && prim::as_lit(&sh[1]) == Some(&BigInt::from(8 * k)) => {
                        sh[0].clone()
                    }
                    _ => return Ok(None),
                }
            };
            match &x {
                None => x = Some(src),
                Some(x0) => {
                    if !Rc::ptr_eq(x0, &src) && !crate::conv::Conv::like(self).conv(depth, x0, &src, b)? {
                        return Ok(None);
                    }
                }
            }
        }
        Ok(x)
    }

    /// `cast_{w→u8}(from_le_bytes_w(bs)) → bs[0]` and
    /// `cast_{w→u8}(wshr_w(from_le_bytes_w(bs), 8k)) → bs[k]` (k < w/8).
    fn byte_extract(&self, w: Width, x: &V) -> Option<V> {
        let (src, k) = match prim::as_prim(x) {
            Some((PrimOp::WShr(w2) | PrimOp::Shr(w2), sh)) if w2 == w => (sh[0].clone(), prim::as_lit(&sh[1])?.to_u64()?),
            _ => (x.clone(), 0),
        };
        if k % 8 != 0 {
            return None;
        }
        let Value::Neu(Neutral { head: Head::Global { def, args }, spine }) = &*src else { return None };
        if !spine.is_empty() || self.env.known.le_bytes_width(*def) != Some(w) {
            return None;
        }
        let Some(Arg::Rel(arr)) = args.first() else { return None };
        let elems = self.array_elems(arr)?;
        elems.get((k / 8) as usize).cloned()
    }

    /// A primitive application.
    pub fn prim(&mut self, mut op: PrimOp, mut args: Vec<V>, mut proofs: Vec<Closure>, depth: Lvl, b: &mut Budget) -> R<V> {
        let _ = depth;
        loop {
            tick(b)?;
            let lits: Option<Vec<&BigInt>> = args.iter().map(prim::as_lit).collect();
            if let Some(lits) = lits {
                return Ok(match prim::eval_lits(op, &lits)? {
                    Some(LitOut::Int(w, n)) => prim::lit_v(w, n),
                    Some(LitOut::Bool(v)) => self.bool_v(v),
                    None => neu(Head::Prim { op, args, proofs }, Vec::new()),
                });
            }
            if let PrimOp::Cast { from, to: Width::U8 } = op
                && let Some(v) = self.byte_extract(from, &args[0])
            {
                return Ok(v);
            }
            match prim::simplify(op, &args, self.env.bool_id) {
                Simp::Keep => return Ok(neu(Head::Prim { op, args, proofs }, Vec::new())),
                Simp::Value(v) => return Ok(v),
                Simp::Rebuild(op2, args2) => {
                    // Keep the (irrelevant) proof closures only if the new op
                    // has the same proof slots (swaps, reassociation).
                    let n = prim::prim_sig(op2).map(|s| s.proofs).unwrap_or(0);
                    if n != proofs.len() {
                        proofs.truncate(n.min(proofs.len()));
                    }
                    op = op2;
                    args = args2;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Fresh variables and fixed-length array eta (§5.9).
    // -----------------------------------------------------------------------

    /// A fresh variable at level `depth` of type `ty`, eta-expanded if `ty` is
    /// a fixed-length array type.
    pub fn fresh(&mut self, depth: Lvl, rel: Rel, ty: &V) -> EnvEntry {
        match rel {
            Rel::Irr => EnvEntry::Irr(irr_var_closure(depth)),
            Rel::Rel => match self.array_shape(depth, ty) {
                Some((elem, n)) => EnvEntry::Rel(self.eta_array(depth, elem, n)),
                None => EnvEntry::Rel(var_v(depth)),
            },
        }
    }

    /// Fresh variables for the fields of constructor `ctor` of `ind` applied
    /// to `params`, at levels `depth, depth + 1, …` — the entries a match arm
    /// is instantiated with. Relevant fields go through [`Ev::fresh`] with
    /// their field type, so a field of fixed-length array type is
    /// eta-expanded (§5.9) exactly as the checker binds it; the checker
    /// (`infer_match`), conversion (`conv_arms`), the quoter and `bvnorm`
    /// all introduce arm fields this way (phase-2 issue K1).
    pub fn arm_fields(&mut self, depth: Lvl, ind: IndId, ctor: u32, params: &[V], b: &mut Budget) -> R<Vec<EnvEntry>> {
        let genv = self.env;
        let Some(c) = genv.inds.get(ind.0 as usize).and_then(|i| i.ctors.get(ctor as usize)) else { return Ok(Vec::new()) };
        let mut fenv: Vec<EnvEntry> = params.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
        let mut out = Vec::with_capacity(c.fields.len());
        for (j, (_, rel, fty)) in c.fields.iter().enumerate() {
            let l = Lvl(depth.0 + j as u32);
            let e = match rel {
                Rel::Irr => EnvEntry::Irr(irr_var_closure(l)),
                Rel::Rel => {
                    let ftv = self.eval(&VEnv(Rc::new(fenv.clone())), l, fty, b)?;
                    self.fresh(l, Rel::Rel, &ftv)
                }
            };
            fenv.push(e.clone());
            out.push(e);
        }
        Ok(out)
    }

    /// Recognize `Σ(l : List T). .Eq(Int, len T l, N)` with literal
    /// `0 ≤ N ≤ 256` (the prelude `Array(T, N)` after unfolding).
    pub fn array_shape(&mut self, depth: Lvl, ty: &V) -> Option<(V, u32)> {
        let env = self.env;
        let known = &env.known;
        let (list, len) = (known.list?, known.len?);
        known.index?;
        let Value::Sigma { snd_rel: Rel::Irr, fst, snd, .. } = &**ty else { return None };
        let Value::Ind { ind, params } = &**fst else { return None };
        if *ind != list || params.len() != 1 {
            return None;
        }
        let mut b = Budget { steps: 10_000 };
        let p = self.inst(snd, EnvEntry::Rel(var_v(depth)), Lvl(depth.0 + 1), &mut b).ok()?;
        let Value::Eq { ty: ety, lhs, rhs } = &*p else { return None };
        if !matches!(&**ety, Value::IntTy(Width::Int)) {
            return None;
        }
        let Value::Neu(Neutral { head: Head::Global { def, args }, spine }) = &**lhs else { return None };
        if *def != len || !spine.is_empty() || args.len() != 2 {
            return None;
        }
        match &args[1] {
            Arg::Rel(l) if matches!(&**l, Value::Neu(Neutral { head: Head::Var(v), spine }) if *v == depth && spine.is_empty()) => {}
            _ => return None,
        }
        let n = prim::as_lit(rhs)?.to_u32()?;
        if n > ARRAY_ETA_MAX {
            return None;
        }
        Some((params[0].clone(), n))
    }

    /// `([index(T, fst x, 0), .., index(T, fst x, N−1)], snd x)` for the
    /// variable `x` at level `depth`, with well-typed proof closures.
    fn eta_array(&mut self, depth: Lvl, elem: V, n: u32) -> V {
        use crate::util::mk;
        let env = self.env;
        let known = &env.known;
        let (list, len, index) = (known.list.unwrap(), known.len.unwrap(), known.index.unwrap());
        let bool_ind = self.env.bool_id;
        let x = var_v(depth);
        let fx = neu(Head::Var(depth), vec![Elim::Fst]);
        // Proof environment: Var(1) = T, Var(0) = x. The bound proofs are
        // certificate-free, so they stay valid whether `len (fst x)` is
        // symbolic or computes to N (when `x` is itself eta-expanded):
        //   0 ≤ k:          refl(Bool, true)
        //   k < len(fst x): transport(Int, N, L, sym(snd x), z. Eq(Bool, lt(k, z), true), refl(Bool, true))
        // with sym(e) := transport(Int, L, N, e, y. Eq(Int, y, L), refl(Int, L)), L := len T (fst x).
        let penv = VEnv(Rc::new(vec![EnvEntry::Rel(elem.clone()), EnvEntry::Rel(x.clone())]));
        let len_of = |t: u32, xv: u32| mk::apps(mk::global(len), [(Rel::Rel, mk::var(t)), (Rel::Rel, mk::fst(mk::var(xv)))]);
        let int = || mk::int_ty(Width::Int);
        let sym = Rc::new(Term::Transport {
            ty: int(),
            lhs: len_of(1, 0),
            rhs: mk::lit(Width::Int, n),
            eq: mk::snd(mk::var(0)),
            motive: mk::eq(int(), mk::var(0), len_of(2, 1)),
            val: mk::refl(int(), len_of(1, 0)),
        });
        let refl_true = mk::refl(mk::bool_ty(bool_ind), mk::bool_lit(bool_ind, true));
        let p0 = Closure { env: VEnv::default(), body: refl_true.clone() };
        let mut elems = Vec::with_capacity(n as usize);
        for k in 0..n {
            let p1 = Closure {
                env: penv.clone(),
                body: Rc::new(Term::Transport {
                    ty: int(),
                    lhs: mk::lit(Width::Int, n),
                    rhs: len_of(1, 0),
                    eq: sym.clone(),
                    motive: mk::eq_bool(bool_ind, prim::prim0(PrimOp::Lt(Width::Int), vec![mk::lit(Width::Int, k), mk::var(0)]), true),
                    val: refl_true.clone(),
                }),
            };
            elems.push(neu(
                Head::Global {
                    def: index,
                    args: vec![
                        Arg::Rel(elem.clone()),
                        Arg::Rel(fx.clone()),
                        Arg::Rel(prim::lit_v(Width::Int, k)),
                        Arg::Irr(p0.clone()),
                        Arg::Irr(p1),
                    ],
                },
                Vec::new(),
            ));
        }
        let mut l: V = Rc::new(Value::Ctor { ind: list, ctor: 0, params: vec![elem.clone()], args: vec![] });
        for e in elems.into_iter().rev() {
            l = Rc::new(Value::Ctor { ind: list, ctor: 1, params: vec![elem.clone()], args: vec![Arg::Rel(e), Arg::Rel(l)] });
        }
        let snd = Closure { env: VEnv(Rc::new(vec![EnvEntry::Rel(x)])), body: crate::util::mk::snd(crate::util::mk::var(0)) };
        Rc::new(Value::Pair { fst: l, snd: Arg::Irr(snd) })
    }
}
