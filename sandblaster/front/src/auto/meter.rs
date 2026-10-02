//! Resource metering of proof search (DESIGN.md §7.2 "budgets", §8.1
//! "within the budget"; docs/fix1-reports.md "prover resource safety").
//!
//! Every prover call is bounded by three limits, and running out of any of
//! them is a **failure** of the call, never a success:
//!
//! * **steps** — the goal's kernel [`Budget`]. Kernel work (evaluation,
//!   conversion, type checking, certificate search) is charged by the kernel
//!   itself. Front-end work — quoting, shifting and substitution, other term
//!   and value traversals, abstraction and motive building, fact scans,
//!   E-matching, case-split bookkeeping, simplex / Fourier–Motzkin pivots,
//!   lemma instantiation — is charged here with [`spend`], one unit per term
//!   or value node visited (or per pivot entry, per candidate), at the same
//!   rate as a kernel step. Charges accumulate in a thread-local counter and
//!   are taken out of the budget by [`settle`], which the provers call at
//!   every search node and before their kernel calls; code without access to
//!   the budget (terms helpers, the quoter wrappers) polls [`exhausted`] to
//!   stop early.
//! * **a wall-clock deadline per goal** ([`goal_timeout`]; default
//!   [`DEFAULT_GOAL_TIMEOUT`], `SANDBLASTER_GOAL_TIMEOUT_MS`, or the prover's
//!   own setting), polled by [`spend`] and [`settle`];
//! * **memory** — the process-wide soft limit of `sandblaster-memguard`
//!   ([`sandblaster_memguard::soft_limit_exceeded`], also polled by the
//!   kernel's step ticker) and a per-goal cap on heap growth
//!   ([`DEFAULT_GOAL_HEAP`]). The cap measures the goal's own thread
//!   (memguard's per-thread count, [`sandblaster_memguard::thread_growth`]):
//!   a goal runs on one thread, and what other threads allocate meanwhile
//!   (the mutation gate's batches run on several) is not its growth.
//!
//! When a limit is hit, the current goal's [`Exhaustion`] is recorded and
//! the next [`settle`] zeroes the budget, so every later kernel call fails
//! with `OutOfFuel` and the search unwinds; the prover then reports the
//! failure with [`describe`] in `AutoFailure::tried`.
//!
//! Limits are scoped per prover call ([`Scope::enter`]); scopes nest (the
//! prover chain opens one per goal, each prover its own): an inner scope's
//! deadline is never later than its parent's. Outside any scope every
//! function here is a no-op, so the helpers can be shared with the
//! elaborator.
//!
//! Determinism (DESIGN.md §15.8): proofs and the emitted code are decided by
//! the step budgets only (same input, same budget, same result). The
//! deadline and the memory limits are safety nets, set well above the
//! budgets: hitting one stops the search (never a success), and it is
//! **recorded as a trip** ([`take_trips`], [`trip_count`]) so that the
//! build reports a resource failure of the build — never a proof result.
//! The elaborator turns an obligation whose prover tripped into
//! `error[resource]` instead of an unproven obligation, and the driver fails
//! a build during which any trip happened (in elaboration, the law audit or
//! the optimizer, whose fallbacks would otherwise make the emitted code
//! depend on the clock), whatever the outcome of the affected goal.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use sandblaster_kernel::api::{Ctx, Env};
use sandblaster_kernel::term::{Idx, IndId, Lvl, Rel, Term, Tm};
use sandblaster_kernel::value::{Arg, Budget, Closure, Elim, EnvEntry, Head, V, VEnv, Value};

/// Default wall-clock limit of one goal (all provers of the chain
/// together), unless `SANDBLASTER_GOAL_TIMEOUT_MS` says otherwise. The step
/// budget normally ends a failing search long before (20M steps take a few
/// seconds); the deadline is the backstop for work the budget
/// under-estimates.
pub const DEFAULT_GOAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Default cap on the heap growth of one goal (bytes): what the goal's
/// thread allocated minus what it freed since the goal's scope opened.
pub const DEFAULT_GOAL_HEAP: usize = 1 << 30;

/// Front-end work between two polls of the clock and the heap.
const POLL_PERIOD: u32 = 256;

/// Why a goal's search was stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exhaustion {
    /// The step budget ran out.
    Steps,
    /// The per-goal deadline passed.
    Deadline,
    /// The process-wide memory soft limit was exceeded.
    Memory,
    /// The goal's heap growth exceeded its cap.
    GoalHeap,
    /// A value too large to read back ([`MAX_QUOTE_COST`]).
    TooLarge,
}

struct Limits {
    deadline: Instant,
    timeout: Duration,
    start: Instant,
    /// This thread's [`sandblaster_memguard::thread_allocated`] when the
    /// scope opened.
    heap0: usize,
    /// The growth of this thread's heap the scope may cause (bytes).
    heap_cap: usize,
    /// The enclosing scope's counters, restored on exit.
    saved: (u64, u64, Option<Exhaustion>, u32),
}

thread_local! {
    /// Number of open scopes.
    static ACTIVE: Cell<u32> = const { Cell::new(0) };
    /// Front-end units charged since the last settle.
    static PENDING: Cell<u64> = const { Cell::new(0) };
    /// Budget steps available at the last settle.
    static AVAIL: Cell<u64> = const { Cell::new(0) };
    static REASON: Cell<Option<Exhaustion>> = const { Cell::new(None) };
    static CALLS: Cell<u32> = const { Cell::new(0) };
    static LIMITS: RefCell<Vec<Limits>> = const { RefCell::new(Vec::new()) };
    /// Safety-net trips of this thread (never restored by scopes).
    static TRIPS: RefCell<Vec<Trip>> = const { RefCell::new(Vec::new()) };
}

/// A safety net that stopped a goal (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trip {
    pub reason: Exhaustion,
    /// [`describe`] of the reason, when it was hit.
    pub note: String,
}

/// Whether a limit is a safety net (wall clock, memory) rather than a
/// deterministic budget (steps, the read-back cost estimate).
pub fn is_safety_net(r: Exhaustion) -> bool {
    matches!(r, Exhaustion::Deadline | Exhaustion::Memory | Exhaustion::GoalHeap)
}

/// The number of safety-net trips of this thread so far.
pub fn trip_count() -> usize {
    TRIPS.with(|t| t.borrow().len())
}

/// Takes (and clears) this thread's safety-net trips.
pub fn take_trips() -> Vec<Trip> {
    TRIPS.with(|t| std::mem::take(&mut *t.borrow_mut()))
}

/// Records a trip (also used by callers that detect one themselves).
pub fn record_trip(reason: Exhaustion) {
    let note = describe(reason);
    TRIPS.with(|t| t.borrow_mut().push(Trip { reason, note }));
}

/// Whether the memguard soft limit was reached on this thread since the last
/// call (the kernel's step ticker then fails evaluations with `OutOfFuel`,
/// outside any meter scope; DESIGN.md §15.8: a resource failure, never a
/// result). Clears the flag.
pub fn memory_soft_limit_reached() -> bool {
    sandblaster_memguard::take_soft_limit_hit()
}

/// The default per-goal deadline: `SANDBLASTER_GOAL_TIMEOUT_MS` (read once;
/// `0` is ignored) or [`DEFAULT_GOAL_TIMEOUT`].
pub fn goal_timeout() -> Duration {
    static T: OnceLock<Duration> = OnceLock::new();
    *T.get_or_init(|| {
        std::env::var("SANDBLASTER_GOAL_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|ms| *ms > 0)
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_GOAL_TIMEOUT)
    })
}

/// The limits of one prover call (RAII: dropping the scope restores the
/// enclosing one).
pub struct Scope {
    _not_send: std::marker::PhantomData<*const ()>,
}

impl Scope {
    /// Opens a scope for a prover call with budget `b`: its deadline is
    /// `timeout` from now (default [`goal_timeout`]), but never later than
    /// the enclosing scope's; its heap cap is [`DEFAULT_GOAL_HEAP`].
    pub fn enter(timeout: Option<Duration>, b: &Budget) -> Scope {
        Scope::enter_capped(timeout, DEFAULT_GOAL_HEAP, b)
    }

    /// [`Scope::enter`] with a cap of `heap_cap` bytes on the growth of
    /// this thread's heap (never more than what the enclosing scope has
    /// left).
    pub fn enter_capped(timeout: Option<Duration>, heap_cap: usize, b: &Budget) -> Scope {
        let now = Instant::now();
        let timeout = timeout.unwrap_or_else(goal_timeout);
        let saved = (PENDING.get(), AVAIL.get(), REASON.get(), CALLS.get());
        LIMITS.with(|l| {
            let mut l = l.borrow_mut();
            let mut deadline = now.checked_add(timeout).unwrap_or(now + Duration::from_secs(1 << 30));
            let mut timeout = timeout;
            let mut heap_cap = heap_cap;
            let heap0 = sandblaster_memguard::thread_allocated();
            if let Some(p) = l.last() {
                if p.deadline < deadline {
                    deadline = p.deadline;
                    timeout = p.timeout;
                }
                // what the enclosing scope has left of its cap
                let used = usize::try_from(heap0.wrapping_sub(p.heap0) as isize).unwrap_or(0);
                heap_cap = heap_cap.min(p.heap_cap.saturating_sub(used));
            }
            l.push(Limits { deadline, timeout, start: now, heap0, heap_cap, saved });
        });
        PENDING.set(0);
        AVAIL.set(b.steps);
        REASON.set(None);
        CALLS.set(0);
        ACTIVE.set(ACTIVE.get() + 1);
        Scope { _not_send: std::marker::PhantomData }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let saved = LIMITS.with(|l| l.borrow_mut().pop().map(|x| x.saved));
        if let Some((p, a, r, c)) = saved {
            PENDING.set(p);
            AVAIL.set(a);
            REASON.set(r);
            CALLS.set(c);
        }
        ACTIVE.set(ACTIVE.get().saturating_sub(1));
    }
}

fn active() -> bool {
    ACTIVE.get() > 0
}

/// Polls the clock and the heap (records the first limit hit).
fn poll_env() {
    if REASON.get().is_some() {
        return;
    }
    let r = LIMITS.with(|l| {
        let l = l.borrow();
        let lim = l.last()?;
        if sandblaster_memguard::soft_limit_exceeded() {
            return Some(Exhaustion::Memory);
        }
        if sandblaster_memguard::thread_growth(lim.heap0) > isize::try_from(lim.heap_cap).unwrap_or(isize::MAX) {
            return Some(Exhaustion::GoalHeap);
        }
        if Instant::now() >= lim.deadline {
            return Some(Exhaustion::Deadline);
        }
        None
    });
    if let Some(x) = r {
        REASON.set(r);
        record_trip(x);
    }
}

/// Charges `n` units of front-end work to the current goal (no-op outside
/// a scope). Returns `false` once the goal is exhausted.
#[inline]
pub fn spend(n: u64) -> bool {
    if !active() {
        return true;
    }
    let p = PENDING.get().saturating_add(n);
    PENDING.set(p);
    if p >= AVAIL.get() && REASON.get().is_none() {
        REASON.set(Some(Exhaustion::Steps));
    }
    let c = CALLS.get().wrapping_add(1);
    CALLS.set(c);
    if c.is_multiple_of(POLL_PERIOD) || n >= 4096 {
        poll_env();
    }
    REASON.get().is_none()
}

/// Takes the pending front-end charges out of `b`, polls the deadline and
/// the heap, and zeroes `b` if the goal is exhausted (so the kernel stops
/// too). Returns whether steps remain. Outside a scope: `b.steps > 0`.
pub fn settle(b: &mut Budget) -> bool {
    if !active() {
        return b.steps > 0;
    }
    b.steps = b.steps.saturating_sub(PENDING.get());
    PENDING.set(0);
    poll_env();
    if REASON.get().is_some() {
        b.steps = 0;
    } else if b.steps == 0 {
        REASON.set(Some(Exhaustion::Steps));
    }
    AVAIL.set(b.steps);
    b.steps > 0
}

/// The limit that stopped the current goal, if any (no poll).
#[inline]
pub fn exhausted() -> Option<Exhaustion> {
    if !active() {
        return None;
    }
    REASON.get()
}

/// Like [`exhausted`], polling the clock and the heap first.
pub fn check() -> Option<Exhaustion> {
    if !active() {
        return None;
    }
    poll_env();
    REASON.get()
}

/// Front-end units still available to the current goal (an upper bound:
/// kernel work since the last [`settle`] is not included); `u64::MAX`
/// outside a scope.
pub fn available() -> u64 {
    if !active() {
        return u64::MAX;
    }
    if REASON.get().is_some() {
        return 0;
    }
    AVAIL.get().saturating_sub(PENDING.get())
}

/// Human-readable reason for `AutoFailure::tried`.
pub fn describe(r: Exhaustion) -> String {
    let (timeout, elapsed, heap0, cap) = LIMITS.with(|l| l.borrow().last().map(|x| (x.timeout, x.start.elapsed(), x.heap0, x.heap_cap)).unwrap_or_default());
    match r {
        Exhaustion::Steps => "budget exhausted".into(),
        Exhaustion::Deadline => format!("deadline exceeded: {} spent, per-goal limit {} (SANDBLASTER_GOAL_TIMEOUT_MS)", secs(elapsed), secs(timeout)),
        Exhaustion::Memory => {
            let (_, soft) = sandblaster_memguard::limits();
            format!("memory soft limit exceeded: heap {} MiB, soft limit {} MiB (SANDBLASTER_MEM_LIMIT_GB)", sandblaster_memguard::allocated() >> 20, soft >> 20)
        }
        Exhaustion::TooLarge => format!("a term too large for proof search (read-back cost over {MAX_QUOTE_COST} nodes)"),
        Exhaustion::GoalHeap => format!(
            "per-goal heap cap exceeded: the goal's thread grew its heap by {} MiB, cap {} MiB",
            sandblaster_memguard::thread_growth(heap0).max(0) >> 20,
            cap >> 20
        ),
    }
}

/// A duration for messages: seconds with one decimal, milliseconds below
/// one second.
fn secs(d: Duration) -> String {
    if d < Duration::from_secs(1) { format!("{} ms", d.as_millis()) } else { format!("{:.1} s", d.as_secs_f64()) }
}

/// The failure note for the current goal: [`describe`] of the recorded
/// reason, or "budget exhausted".
pub fn failure_note() -> String {
    describe(exhausted().unwrap_or(Exhaustion::Steps))
}

// ---------------------------------------------------------------------------
// Cost estimates.
// ---------------------------------------------------------------------------

/// Estimated cost of reading back `v` (a value in `ctx`, of type `ty` when
/// known) with the kernel's quoter (`Env::quote_typed` when `typed`, else
/// `Env::quote`), counting up to `cap`. This is a dry run of the quoter's
/// traversal that builds no term: it visits the same nodes with the same
/// memoization (neutrals and constructors with fields, by address and
/// depth), instantiates the same closures with the same fresh variables
/// (array binders eta-expanded) and evaluates them — on its own budget of
/// `cap` steps — and follows the same expected types (typed read-back
/// quotes the Σ type of every pair). A value can be tiny and still read
/// back to millions of nodes (a stuck match whose arms run a whole verifier
/// symbolically, pairs whose types are re-read at every occurrence), so no
/// cheaper measure of the value itself bounds the read-back. Returns `cap`
/// when the estimate reaches it.
pub fn value_cost(env: &Env, ctx: &Ctx, v: &V, ty: Option<&V>, typed: bool, cap: u64) -> u64 {
    let types: Vec<Option<V>> = if typed { ctx.entries.iter().map(|e| Some(e.ty.clone())).collect() } else { Vec::new() };
    let mut c = DryQuote { env, typed, types, n: 0, cap, memo: HashSet::new(), keep: Vec::new(), decls: HashMap::new(), b: Budget { steps: cap } };
    c.q(ctx.depth().0, v, ty);
    c.cost()
}

struct DryQuote<'e> {
    env: &'e Env,
    typed: bool,
    /// Types of the variables by level (typed read-back).
    types: Vec<Option<V>>,
    n: u64,
    cap: u64,
    memo: HashSet<(usize, u32)>,
    /// Memoized values, kept alive so their addresses are not reused.
    keep: Vec<V>,
    decls: HashMap<IndId, Rc<sandblaster_kernel::term::InductiveDecl>>,
    b: Budget,
}

impl DryQuote<'_> {
    fn cost(&self) -> u64 {
        self.n.saturating_add(self.cap - self.b.steps).min(self.cap)
    }

    fn full(&self) -> bool {
        self.cost() >= self.cap
    }

    fn fresh(&mut self, d: u32, rel: Rel, ty: &V) -> EnvEntry {
        let e = self.env.fresh_var(Lvl(d), rel, ty);
        if self.typed {
            if self.types.len() <= d as usize {
                self.types.resize(d as usize + 1, None);
            }
            self.types[d as usize] = Some(ty.clone());
        }
        e
    }

    fn inst(&mut self, c: &Closure, es: Vec<EnvEntry>, d: u32) -> Option<V> {
        let mut env: Vec<EnvEntry> = c.env.0.as_ref().clone();
        env.extend(es);
        self.env.eval(&VEnv(Rc::new(env)), Lvl(d), &c.body, &mut self.b).ok()
    }

    fn inst_ty(&mut self, c: &Closure, es: Vec<EnvEntry>, d: u32) -> Option<V> {
        if !self.typed {
            return None;
        }
        self.inst(c, es, d)
    }

    fn q(&mut self, d: u32, v: &V, ty: Option<&V>) {
        if self.full() {
            return;
        }
        let memo = matches!(&**v, Value::Neu(_)) || matches!(&**v, Value::Ctor { args, .. } if !args.is_empty());
        if memo {
            if !self.memo.insert((Rc::as_ptr(v) as *const () as usize, d)) {
                return;
            }
            self.keep.push(v.clone());
        }
        self.n += 1;
        match &**v {
            Value::Sort(_) | Value::IntTy(_) | Value::Lit { .. } => {}
            Value::Pi { rel, dom, cod, .. } => {
                self.q(d, dom, None);
                let x = self.fresh(d, *rel, dom);
                self.q_under(d, cod, vec![x], None);
            }
            Value::Lam { rel, dom, body, .. } => {
                self.q(d, dom, None);
                let x = self.fresh(d, *rel, dom);
                let body_ty = match ty.map(|t| &**t) {
                    Some(Value::Pi { cod, .. }) => self.inst_ty(cod, vec![x.clone()], d + 1),
                    _ => None,
                };
                self.q_under(d, body, vec![x], body_ty.as_ref());
            }
            Value::Sigma { fst, snd, .. } => {
                self.q(d, fst, None);
                let x = self.fresh(d, Rel::Rel, fst);
                self.q_under(d, snd, vec![x], None);
            }
            // the eta expansion of an array variable reads back as the variable
            Value::Pair { snd: Arg::Irr(c), .. } if c.env.0.len() == 1 && matches!(&*c.body, Term::Snd(x) if matches!(&**x, Term::Var(Idx(0)))) => {}
            Value::Pair { fst, snd } => match ty.map(|t| &**t) {
                Some(Value::Sigma { fst: a, snd: bcl, .. }) if self.typed => {
                    let (a, bcl) = (a.clone(), bcl.clone());
                    self.q(d, ty.unwrap(), None);
                    self.q(d, fst, Some(&a));
                    let bt = self.inst_ty(&bcl, vec![EnvEntry::Rel(fst.clone())], d);
                    self.arg(d, snd, bt.as_ref());
                }
                _ => {
                    self.q(d, fst, None);
                    self.arg(d, snd, None);
                }
            },
            Value::Eq { ty: t, lhs, rhs } => {
                self.q(d, t, None);
                self.q(d, lhs, Some(t));
                self.q(d, rhs, Some(t));
            }
            Value::Refl { ty: t, val } => {
                self.q(d, t, None);
                self.q(d, val, Some(t));
            }
            Value::Ind { params, .. } => params.iter().for_each(|p| self.q(d, p, None)),
            Value::Ctor { ind, ctor, params, args } => {
                params.iter().for_each(|p| self.q(d, p, None));
                let ftys = if self.typed { self.field_types(d, *ind, *ctor as usize, params, args) } else { Vec::new() };
                for (i, a) in args.iter().enumerate() {
                    self.arg(d, a, ftys.get(i).and_then(|t| t.as_ref()));
                }
            }
            Value::Neu(n) => self.neutral(d, n),
        }
    }

    fn decl(&mut self, ind: IndId) -> Option<Rc<sandblaster_kernel::term::InductiveDecl>> {
        if let Some(x) = self.decls.get(&ind) {
            return Some(x.clone());
        }
        let x = Rc::new(self.env.inductive_decl(ind)?);
        self.decls.insert(ind, x.clone());
        Some(x)
    }

    fn field_types(&mut self, d: u32, ind: IndId, ctor: usize, params: &[V], args: &[Arg]) -> Vec<Option<V>> {
        let Some(decl) = self.decl(ind) else { return Vec::new() };
        let Some(c) = decl.ctors.get(ctor) else { return Vec::new() };
        let mut venv: Vec<EnvEntry> = params.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
        let mut out = Vec::with_capacity(c.fields.len());
        for (i, (_, _, fty)) in c.fields.iter().enumerate() {
            out.push(self.env.eval(&VEnv(Rc::new(venv.clone())), Lvl(d), fty, &mut self.b).ok());
            match args.get(i) {
                Some(a) => venv.push(super::util::arg_entry(a)),
                None => break,
            }
        }
        out
    }

    fn arg(&mut self, d: u32, a: &Arg, ty: Option<&V>) {
        match a {
            Arg::Rel(v) => self.q(d, v, ty),
            Arg::Irr(c) => self.q_clo(d, c, 0),
        }
    }

    fn neutral(&mut self, d: u32, n: &sandblaster_kernel::value::Neutral) {
        let mut ty: Option<V> = match &n.head {
            Head::Var(l) => self.types.get(l.0 as usize).cloned().flatten(),
            Head::Global { def, args } => {
                let mut ty = if self.typed { self.env.global_type_value(*def) } else { None };
                for a in args {
                    let (dom, cod) = match ty.as_deref() {
                        Some(Value::Pi { dom, cod, .. }) => (Some(dom.clone()), Some(cod.clone())),
                        _ => (None, None),
                    };
                    self.arg(d, a, dom.as_ref());
                    ty = cod.and_then(|c| self.inst_ty(&c, vec![super::util::arg_entry(a)], d));
                }
                ty
            }
            Head::Prim { args, proofs, .. } => {
                args.iter().for_each(|a| self.q(d, a, None));
                proofs.iter().for_each(|c| self.q_clo(d, c, 0));
                None
            }
            Head::Absurd { ty } => {
                self.q(d, ty, None);
                Some(ty.clone())
            }
            Head::Transport { ty, lhs, rhs, motive, val } => {
                self.q(d, ty, None);
                self.q(d, lhs, Some(ty));
                self.q(d, rhs, Some(ty));
                let y = self.fresh(d, Rel::Rel, ty);
                self.q_under(d, motive, vec![y], None);
                let val_ty = self.inst_ty(motive, vec![EnvEntry::Rel(lhs.clone())], d);
                self.q(d, val, val_ty.as_ref());
                self.inst_ty(motive, vec![EnvEntry::Rel(rhs.clone())], d)
            }
            Head::Axiom { args, .. } => {
                args.iter().for_each(|a| self.arg(d, a, None));
                None
            }
        };
        for (i, e) in n.spine.iter().enumerate() {
            if self.full() {
                return;
            }
            self.n += 1;
            match e {
                Elim::App(a) => {
                    let (dom, cod) = match ty.as_deref() {
                        Some(Value::Pi { dom, cod, .. }) => (Some(dom.clone()), Some(cod.clone())),
                        _ => (None, None),
                    };
                    self.arg(d, a, dom.as_ref());
                    ty = cod.and_then(|c| self.inst_ty(&c, vec![super::util::arg_entry(a)], d));
                }
                Elim::Fst => {
                    ty = match ty.as_deref() {
                        Some(Value::Sigma { fst, .. }) => Some(fst.clone()),
                        _ => None,
                    };
                }
                Elim::Snd => ty = None,
                Elim::Match { ind, params, motive, arms } => {
                    params.iter().for_each(|p| self.q(d, p, None));
                    let ind_v = Rc::new(Value::Ind { ind: *ind, params: params.clone() });
                    let y = self.fresh(d, Rel::Rel, &ind_v);
                    self.q_under(d, motive, vec![y], None);
                    for (k, arm) in arms.iter().enumerate() {
                        let Some(es) = self.arm_fields(*ind, k, params, d) else {
                            self.n = self.cap;
                            return;
                        };
                        let d2 = d + es.len() as u32;
                        let arm_ty = if self.typed {
                            let cv = Rc::new(Value::Ctor { ind: *ind, ctor: k as u32, params: params.clone(), args: es.iter().map(super::util::entry_arg).collect() });
                            self.inst_ty(motive, vec![EnvEntry::Rel(cv)], d2)
                        } else {
                            None
                        };
                        self.q_under(d, arm, es, arm_ty.as_ref());
                    }
                    ty = if self.typed { self.inst_ty(motive, vec![EnvEntry::Rel(super::util::prefix(n, i))], d) } else { None };
                }
            }
        }
    }

    /// Fresh entries for the fields of constructor `k`, as the quoter binds
    /// them (array fields eta-expanded, so evaluation proceeds through
    /// them); `None` when the budget runs out.
    fn arm_fields(&mut self, ind: IndId, k: usize, params: &[V], d: u32) -> Option<Vec<EnvEntry>> {
        let decl = self.decl(ind)?;
        let Some(c) = decl.ctors.get(k) else { return Some(Vec::new()) };
        let mut fenv: Vec<EnvEntry> = params.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
        let mut es = Vec::with_capacity(c.fields.len());
        for (j, (_, rel, fty)) in c.fields.iter().enumerate() {
            let l = d + j as u32;
            let e = match rel {
                Rel::Irr => self.env.fresh_var(Lvl(l), Rel::Irr, &Rc::new(Value::Sort(sandblaster_kernel::term::Sort::Type))),
                Rel::Rel => match self.env.eval(&VEnv(Rc::new(fenv.clone())), Lvl(l), fty, &mut self.b) {
                    Ok(ft) => self.fresh(l, Rel::Rel, &ft),
                    Err(_) if self.b.steps == 0 => return None,
                    Err(_) => EnvEntry::Rel(super::util::neu_var(l)),
                },
            };
            fenv.push(e.clone());
            es.push(e);
        }
        Some(es)
    }

    /// A closure instantiated with fresh variables and evaluated (by
    /// substitution if the evaluation fails).
    fn q_under(&mut self, d: u32, c: &Closure, es: Vec<EnvEntry>, ty: Option<&V>) {
        if self.full() {
            return;
        }
        let nb = es.len() as u32;
        match self.inst(c, es, d + nb) {
            Some(v) => self.q(d + nb, &v, ty),
            None if self.b.steps > 0 => self.q_clo(d, c, nb),
            None => {}
        }
    }

    /// A closure read back by substitution (irrelevant closures, failed
    /// evaluations): every distinct body node, and the environment value of
    /// every free-variable occurrence at its binder depth (an irrelevant
    /// closure bound in the environment is re-read at each occurrence).
    fn q_clo(&mut self, d: u32, c: &Closure, binders: u32) {
        if self.full() {
            return;
        }
        let room = self.cap.saturating_sub(self.n);
        self.n += term_size(&c.body, room);
        let mut occ: Vec<(u32, u32)> = Vec::new();
        crate::elab::tm::any_node_depth(&c.body, &mut |t, k| {
            if let Term::Var(Idx(i)) = t
                && *i >= k + binders
            {
                occ.push((*i - k - binders, k + binders));
            }
            false
        });
        let len = c.env.0.len();
        for (i, k) in occ {
            if self.full() {
                return;
            }
            let Some(e) = (i as usize).checked_add(1).and_then(|x| len.checked_sub(x)).and_then(|j| c.env.0.get(j)) else { continue };
            match e {
                EnvEntry::Rel(v) => self.q(d + k, v, None),
                EnvEntry::Irr(c2) => self.q_clo(d + k, c2, 0),
            }
        }
    }
}

/// Distinct nodes of a term graph, counting up to `cap`.
pub fn term_size(t: &Tm, cap: u64) -> u64 {
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    crate::elab::tm::size_capped(t, cap) as u64
}

/// Largest value (estimated read-back cost, [`value_cost`]) a prover reads
/// back. The estimate is conservative (1.3–3× the nodes actually read
/// back); the largest read-back of the test suites and the QMDB build is
/// estimated at 640k (233k nodes, a Merkle law). Values beyond this bound
/// (e.g. a fact about the fully unfolded verifier: estimated 9.8M, 3.1M
/// nodes, ~1.5 GiB to read back) are useless to the search.
pub const MAX_QUOTE_COST: u64 = 2_000_000;

/// Charges the estimated cost of quoting `v` and says whether the quote is
/// affordable: within the goal's remaining budget and [`MAX_QUOTE_COST`].
/// An unaffordable quote exhausts the goal (the caller must not quote; it
/// returns a placeholder, the search stops at its next [`settle`] and the
/// prover fails).
pub fn charge_quote(env: &Env, ctx: &Ctx, v: &V, ty: Option<&V>, typed: bool) -> bool {
    if !active() {
        return true;
    }
    let avail = available();
    if avail == 0 {
        return false;
    }
    let limit = avail.min(MAX_QUOTE_COST);
    let cost = value_cost(env, ctx, v, ty, typed, limit.saturating_add(1));
    if cost > avail {
        spend(avail);
        return false;
    }
    if cost > MAX_QUOTE_COST {
        spend(cost);
        if REASON.get().is_none() {
            REASON.set(Some(Exhaustion::TooLarge));
        }
        return false;
    }
    spend(cost)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_charge_settle_and_restore() {
        let mut b = Budget { steps: 1000 };
        assert!(spend(10_000), "no-op outside a scope");
        {
            let _s = Scope::enter(Some(Duration::from_secs(60)), &b);
            assert!(spend(100));
            assert!(settle(&mut b));
            assert_eq!(b.steps, 900);
            {
                let mut inner = Budget { steps: 50 };
                let _t = Scope::enter(None, &inner);
                assert!(!spend(60));
                assert_eq!(exhausted(), Some(Exhaustion::Steps));
                assert!(!settle(&mut inner));
                assert_eq!(inner.steps, 0);
            }
            // the outer scope is restored
            assert_eq!(exhausted(), None);
            assert!(spend(1));
            assert!(settle(&mut b));
            assert_eq!(b.steps, 899);
        }
        assert_eq!(exhausted(), None);
    }

    #[test]
    fn deadline_zeroes_the_budget() {
        let mut b = Budget { steps: u64::MAX / 2 };
        let n = trip_count();
        let _s = Scope::enter(Some(Duration::from_millis(1)), &b);
        std::thread::sleep(Duration::from_millis(5));
        assert!(!settle(&mut b));
        assert_eq!(b.steps, 0);
        assert_eq!(exhausted(), Some(Exhaustion::Deadline));
        assert!(describe(Exhaustion::Deadline).contains("deadline exceeded"));
        // the safety net is recorded as a trip (a resource failure of the
        // build), a step exhaustion is not
        assert_eq!(trip_count(), n + 1);
        assert!(take_trips().iter().any(|t| t.reason == Exhaustion::Deadline && is_safety_net(t.reason)));
    }

    #[test]
    fn step_exhaustion_is_not_a_trip() {
        let _ = take_trips();
        let mut b = Budget { steps: 10 };
        let _s = Scope::enter(Some(Duration::from_secs(60)), &b);
        assert!(!spend(100));
        assert!(!settle(&mut b));
        assert_eq!(exhausted(), Some(Exhaustion::Steps));
        assert_eq!(trip_count(), 0);
        assert!(!is_safety_net(Exhaustion::Steps) && !is_safety_net(Exhaustion::TooLarge));
    }
}
