//! **Lockstep refinement** (layered proofs, DESIGN.md §15.2): an exec
//! function `#[refines(m::f)]` whose target is a spec function written in
//! the shape of the code — a function of a `#[model]` module (the code read
//! over numbers and sequences), or a spec function the code mirrors — is
//! proven with no proof text by walking the two bodies together.
//!
//! # The walk
//!
//! The refinement walk (`elab::refines`) walks the exec body; at each of its
//! tails `L` the goal is `Eq(T, L, f(b̄))`. The lockstep walks `f`'s body at
//! `b̄` the same way ([`Elab::walk_body`]: `let`s bound, matches split with
//! their path equations; an arm whose path equation contradicts the code's
//! is closed by `absurd`, [`Elab::ls_prune`]) and meets each tail `M` of the
//! target with `L` ([`Elab::meet`]):
//!
//! 1. the sides convert: `refl`;
//! 2. a side that is a *choice* — a `let`-bound variable whose value is a
//!    match (`let child = if left { .. } else { .. }`), or a match — is
//!    walked through its value, the variable replaced by each outcome (so
//!    exec code keeps its natural `let`-bound shape);
//! 3. structure, argument by argument: a fact `Eq(T, X, g(c̄))` about the
//!    code side (a callee's refinement at its call, an induction hypothesis
//!    of a recursive call) carries the code side to `g(c̄)`; the same
//!    function on both sides meets argument by argument (transport along
//!    each argument equation, `dep_congruence`); the same constructor field
//!    by field;
//! 4. a side headed by a non-recursive spec function with a body is walked
//!    one step (its body at the arguments);
//! 5. otherwise the equation is an **atom**: the prover chain, with a
//!    fraction of the goal budget (arithmetic across the view, the bridges
//!    of the standard library as rules of `auto`).
//!
//! # Cost control
//!
//! Every step is charged to a deterministic budget ([`LOCKSTEP_STEPS`];
//! atoms and contradiction checks cost more than structural steps). Within
//! one lockstep, equations already met in the same context are memoized
//! (the key is the context itself, which is persistent and kept alive by
//! the memo, and the equation). A lockstep that fails reports the first
//! step where code and target differ (the deepest equation it could not
//! decompose, with the branch conditions that lead there).
//!
//! # Trust
//!
//! None is added: the lockstep builds an ordinary proof term (the mirrored
//! walks, `transport` along `Delta` for a recursive or opaque target,
//! `eq::trans`/`eq::cong` and transports for the decompositions, the
//! prover's proofs at the atoms), which the kernel checks with the
//! refinement lemma. A result is kept only if every obligation it recorded
//! is proven; otherwise its records are dropped.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use sandblaster_kernel::api::CtxEntry;
use sandblaster_kernel::term::{DefKind, GlobalId, Rel, Term, Tm};
use sandblaster_kernel::util::{mk, shift};

use super::ensures::{strip_lams, WalkGoal};
use super::{Elab, ElabError, ErrKind, R};
use crate::prover::ObligationKind;
use crate::span::Span;

/// The step budget of one lockstep (deterministic: the result never
/// depends on the machine). Charged per structural step ([`STEP_COST`]),
/// per split of a choice ([`SPLIT_COST`]), per contradiction check
/// ([`PRUNE_COST`]) and per prover attempt at an atom ([`ATOM_COST`]).
pub const LOCKSTEP_STEPS: u64 = 6000;
const STEP_COST: u64 = 1;
const SPLIT_COST: u64 = 2;
const PRUNE_COST: u64 = 4;
const ATOM_COST: u64 = 16;
/// The prover's budget divisor at an atom and at a contradiction check.
const ATOM_DIV: u64 = 16;
const PRUNE_DIV: u64 = 16;
/// How many nested one-step unfoldings of target-side functions a meet may
/// take ([`Elab::meet`] rule 4).
const STEP_FUEL: u32 = 4;
/// How deep decompositions may nest (a guard against facts that lead back
/// to each other).
const MAX_DEPTH: u32 = 48;

thread_local! {
    /// The running locksteps (innermost last).
    static STATE: RefCell<Vec<LsState>> = const { RefCell::new(Vec::new()) };
    /// On while the refinement walk of a function whose target the lockstep
    /// may meet runs ([`Elab::refines_walk`]): the induction hypotheses then
    /// include the recursive calls inside `let`-bound choices
    /// (`elab::ensures::with_induction_hyps`).
    pub(super) static IH_IN_CHOICES: Cell<bool> = const { Cell::new(false) };
    /// The prover's budget divisor inside a lockstep (1 outside).
    pub(super) static PROVER_DIV: Cell<u64> = const { Cell::new(1) };
    /// The report of the last lockstep that failed (for the refinement's
    /// diagnostic).
    static LAST_FAILURE: RefCell<Option<String>> = const { RefCell::new(None) };
    /// Which globals are functions of a `#[model]` module (cache).
    static MODEL_CACHE: RefCell<HashMap<GlobalId, bool>> = RefCell::new(HashMap::new());
}

/// Counters of one lockstep (`SANDBLASTER_TRACE_LOCKSTEP`).
#[derive(Default, Clone, Debug)]
pub struct LsStats {
    pub steps: u64,
    pub atoms: u64,
    pub atoms_failed: u64,
    pub prunes: u64,
    pub pruned: u64,
    pub splits: u64,
    pub memo_hits: u64,
}

struct LsState {
    left: u64,
    exhausted: bool,
    stats: LsStats,
    /// `(context, facts, fingerprint)` ↦ equations met there: the equation,
    /// the context (kept alive, so its address is never reused), the result.
    memo: HashMap<(usize, usize, u64), Vec<(Tm, Rc<Vec<CtxEntry>>, Option<Tm>)>>,
    /// Where the walk is (for the report): target branches, arguments.
    crumbs: Vec<String>,
    /// The depth at which the lockstep started (its own path facts are the
    /// ones above it).
    base: u32,
    /// The equations being met (outermost first), with their contexts: an
    /// equation that comes back while it is being met is not met again.
    stack: Vec<(usize, Tm)>,
}

/// Why an equation could not be met: the deepest atom that failed, with the
/// walk's position.
#[derive(Clone, Debug)]
pub struct Divergence {
    /// How many decompositions deep the atom was.
    pub depth: u32,
    pub text: String,
}

type Met = Result<Tm, Divergence>;

fn with_state<T>(f: impl FnOnce(&mut LsState) -> T) -> Option<T> {
    STATE.with(|s| s.borrow_mut().last_mut().map(f))
}

/// Charges `cost` steps to the running lockstep; `false` when the budget is
/// exhausted.
fn charge(cost: u64) -> bool {
    with_state(|s| {
        s.stats.steps += cost;
        if s.left < cost {
            s.exhausted = true;
            s.left = 0;
            false
        } else {
            s.left -= cost;
            true
        }
    })
    .unwrap_or(true)
}

fn stat(f: impl FnOnce(&mut LsStats)) {
    with_state(|s| f(&mut s.stats));
}

fn crumb_push(c: String) {
    with_state(|s| s.crumbs.push(c));
}

fn crumb_pop() {
    with_state(|s| {
        s.crumbs.pop();
    });
}

fn crumbs() -> Vec<String> {
    with_state(|s| s.crumbs.clone()).unwrap_or_default()
}

/// Forgets the per-crate caches (a new crate is elaborated).
pub fn reset() {
    MODEL_CACHE.with(|c| c.borrow_mut().clear());
    LAST_FAILURE.with(|f| *f.borrow_mut() = None);
}

/// Takes the report of the last failed lockstep.
pub(super) fn take_failure() -> Option<String> {
    LAST_FAILURE.with(|f| f.borrow_mut().take())
}

/// The error that aborts a walk at the first leaf the lockstep cannot meet
/// (the other branches are not tried: the attempt has failed).
fn abort(span: Span) -> ElabError {
    ElabError { span, msg: "lockstep: a tail differs".into(), kind: ErrKind::Blocked }
}

impl<'a> Elab<'a> {
    /// Whether the spec function `s` belongs to a `#[model]` module.
    pub(super) fn is_model_fn(&self, s: GlobalId) -> bool {
        if let Some(b) = MODEL_CACHE.with(|c| c.borrow().get(&s).copied()) {
            return b;
        }
        let b = self.globals.iter().any(|(id, g)| matches!(g, super::ItemGlobal::Def(x) if *x == s) && self.krate.in_model_module(*id));
        MODEL_CACHE.with(|c| c.borrow_mut().insert(s, b));
        b
    }

    /// Whether the lockstep can meet a goal whose right side is headed by
    /// `s`: a spec function with a body.
    pub(super) fn lockstep_target(&self, s: GlobalId) -> bool {
        self.env.global_kind(s) == Some(DefKind::Spec) && self.env.global_body(s).is_some()
    }

    /// Runs `f` as one lockstep with a fresh budget; on failure keeps the
    /// report ([`take_failure`]).
    fn ls_run(&mut self, what: &str, f: impl FnOnce(&mut Self) -> R<Met>) -> R<Option<Tm>> {
        let base = self.depth();
        STATE.with(|s| s.borrow_mut().push(LsState { left: LOCKSTEP_STEPS, exhausted: false, stats: LsStats::default(), memo: HashMap::new(), crumbs: vec![], base, stack: vec![] }));
        let t0 = std::time::Instant::now();
        let r = f(self);
        let st = STATE.with(|s| s.borrow_mut().pop()).expect("lockstep state");
        if std::env::var_os("SANDBLASTER_TRACE_LOCKSTEP").is_some() {
            eprintln!(
                "lockstep: {} in {}: {} after {:?}: {:?}",
                what,
                self.f.name,
                match &r {
                    Ok(Ok(_)) => "met",
                    Ok(Err(_)) => "failed",
                    Err(_) => "error",
                },
                t0.elapsed(),
                st.stats
            );
        }
        match r? {
            Ok(p) => Ok(Some(p)),
            Err(d) => {
                let mut text = d.text;
                if st.exhausted {
                    text = format!("the lockstep's step budget ({LOCKSTEP_STEPS}) ran out; the last step it could not take: {text}");
                }
                if std::env::var_os("SANDBLASTER_TRACE_LOCKSTEP").is_some() {
                    eprintln!("lockstep: {what}: {}", text.chars().take(4000).collect::<String>());
                }
                LAST_FAILURE.with(|f| *f.borrow_mut() = Some(format!("lockstep with `{what}`: {text}")));
                Ok(None)
            }
        }
    }

    /// The lockstep at a tail of the refinement walk: the goal `Eq(T, L,
    /// f(b̄))` with `f` a spec function with a body (see the module docs).
    /// `None` (records dropped, [`take_failure`] set) unless every
    /// obligation is proven.
    pub(super) fn lockstep_leaf(&mut self, goal: &Tm, span: Span) -> R<Option<Tm>> {
        let Term::Eq { ty, lhs, rhs } = &**goal else { return Ok(None) };
        let (head, args) = super::items::spine(rhs);
        let Term::Global(s) = &*head else { return Ok(None) };
        let s = *s;
        if !self.lockstep_target(s) || self.env.global_arity(s) != Some(args.len() as u32) || args.is_empty() {
            return Ok(None);
        }
        let name = self.env.global_name(s).map(|n| n.to_string()).unwrap_or_default();
        let (ty, lhs, rhs) = (ty.clone(), lhs.clone(), rhs.clone());
        self.ls_run(&name, |el| {
            let rec = el.save_records();
            let r = el.ls_step(&ty, &lhs, &rhs, s, &args, false, span, STEP_FUEL, 0)?;
            if r.is_err() || !el.records_proven_since(&rec) {
                let _ = el.split_records(&rec);
                return Ok(Err(r.err().unwrap_or(Divergence { depth: 0, text: "an obligation of the walk is unproven".into() })));
            }
            Ok(r)
        })
    }

    /// `by_lockstep()`: the goal `Eq(T, L, R)` of a proof by the lockstep
    /// (both sides ghost): met as a lockstep tail ([`Elab::meet`]), or by one
    /// step of a side headed by a spec function with a body — recursive ones
    /// included — each outcome met with the other side. `None`, records
    /// dropped, on failure.
    pub(super) fn by_lockstep(&mut self, goal: &Tm, span: Span) -> R<Option<Tm>> {
        let Term::Eq { ty, lhs, rhs } = &**goal else { return Ok(None) };
        let (ty, lhs, rhs) = (ty.clone(), lhs.clone(), rhs.clone());
        self.ls_run("by_lockstep()", |el| {
            let rec = el.save_records();
            let mut best: Option<Divergence> = None;
            // the same function on both sides: argument by argument
            if let Some(r) = el.same_head(&ty, &lhs, &rhs, span, STEP_FUEL, 0)? {
                match r {
                    Ok(p) if el.records_proven_since(&rec) => return Ok(Ok(p)),
                    Ok(_) => {
                        let _ = el.split_records(&rec);
                    }
                    Err(d) => best = deeper(best, d),
                }
            }
            // one step of a side headed by a spec function with a body
            for left in [true, false] {
                let side = if left { &lhs } else { &rhs };
                let other = if left { &rhs } else { &lhs };
                let (head, args) = super::items::spine(side);
                let Term::Global(f) = &*head else { continue };
                let f = *f;
                if !el.lockstep_target(f) || el.env.global_arity(f) != Some(args.len() as u32) || args.is_empty() {
                    continue;
                }
                let r = el.ls_step(&ty, other, side, f, &args, left, span, STEP_FUEL, 0)?;
                match r {
                    Ok(p) if el.records_proven_since(&rec) => return Ok(Ok(p)),
                    Ok(_) => {
                        let _ = el.split_records(&rec);
                    }
                    Err(d) => {
                        let _ = el.split_records(&rec);
                        best = deeper(best, d);
                    }
                }
            }
            // the sides' structure (no atom at the top: the closer's fallback
            // is the prover on the whole goal)
            match el.meet(&ty, &lhs, &rhs, span, STEP_FUEL, 0, false)? {
                Ok(p) if el.records_proven_since(&rec) => return Ok(Ok(p)),
                Ok(_) => {
                    let _ = el.split_records(&rec);
                }
                Err(d) => best = deeper(best, d),
            }
            Ok(Err(best.unwrap_or(Divergence { depth: 0, text: "neither side is a call of a spec function with a body".into() })))
        })
    }

    /// One step of a side `f(ā)` of `Eq(T, ·, ·)` (`left`: the stepped side
    /// is the equation's left): `f`'s body at `ā` walked, each tail met with
    /// `other`; transported along `Delta(f; ā)` when `f` is recursive or
    /// opaque. The walk stops at the first tail that cannot be met.
    #[allow(clippy::too_many_arguments)]
    fn ls_step(&mut self, ty: &Tm, other: &Tm, side: &Tm, f: GlobalId, args: &[Tm], left: bool, span: Span, fuel: u32, depth: u32) -> R<Met> {
        let Some(body) = self.env.global_body(f) else { return Ok(Err(Divergence { depth, text: "the target has no body".into() })) };
        let arity = args.len() as u32;
        let inst = super::tm::subst_closed(&strip_lams(&body, arity), args);
        let recursive = super::tm::any_node(&body, &mut |n| matches!(n, Term::Global(h) if *h == f));
        let opaque = self.env.global_opaque(f) == Some(true);
        let name = self.env.global_name(f).map(|n| n.to_string()).unwrap_or_default();
        if trace_level() >= 3 && std::env::var("SANDBLASTER_TRACE_LOCKSTEP_FN").is_ok_and(|x| x.split(',').any(|y| self.f.name.contains(y))) {
            eprintln!("  step `{name}`: {}", self.show_tm(&inst).chars().take(20000).collect::<String>());
        }
        crumb_push(format!("in the body of `{name}`"));
        let saved = self.f.scope.clone();
        let mut g = SideGoal { ty: ty.clone(), other: other.clone(), base: self.depth(), span, left, fuel, depth, failure: None };
        let walked = self.walk_body(&inst, &mut g);
        self.f.scope = saved;
        crumb_pop();
        let p = match walked {
            Ok(p) => p,
            Err(e) if e.msg.starts_with("lockstep:") => return Ok(Err(g.failure.unwrap_or(Divergence { depth, text: "a tail differs".into() }))),
            Err(e) => return Ok(Err(Divergence { depth, text: format!("the walk of `{name}` failed: {}", e.msg) })),
        };
        if !(recursive || opaque) {
            return Ok(Ok(p));
        }
        // transport(T, inst, f ā, sym(delta(f; ā)), z. G[z], p)
        let delta = Rc::new(Term::Delta { def: f, args: args.to_vec() });
        let sym = mk::apps(mk::global(self.p.g("eq::sym")), [(Rel::Rel, ty.clone()), (Rel::Rel, side.clone()), (Rel::Rel, inst.clone()), (Rel::Rel, delta)]);
        let motive = if left { mk::eq(shift(ty, 1), mk::var(0), shift(other, 1)) } else { mk::eq(shift(ty, 1), shift(other, 1), mk::var(0)) };
        Ok(Ok(Rc::new(Term::Transport { ty: ty.clone(), lhs: inst, rhs: side.clone(), eq: sym, motive, val: p })))
    }

    /// An arm of a target-side (or choice) walk whose path equation
    /// contradicts the facts in scope (the code's path equations, the
    /// arms taken so far): a proof of `Empty`, found by the prover with a
    /// small budget. `None` when the arm is possible (or the check gives up).
    pub(super) fn ls_prune(&mut self, span: Span) -> R<Option<Tm>> {
        if !charge(PRUNE_COST) {
            return Ok(None);
        }
        stat(|s| s.prunes += 1);
        // a `bool` test: its other value, then `false ≠ true`
        if let Some(p) = self.ls_prune_test(span)? {
            stat(|s| s.pruned += 1);
            return Ok(Some(p));
        }
        let empty = mk::ind(self.env.empty_ind(), vec![]);
        let rec = self.save_records();
        // only the facts that share a variable with the arm's own path
        // equation (through `let`s, two rounds): a contradiction of the arm
        // lives there, and a large context (a buffer's element facts) would
        // only exhaust the check's budget
        let hidden_before = self.f.scope.hidden.clone();
        let d = self.depth();
        // the arm's path equation: the newest statement in scope
        if let Some(last) = self.f.scope.fact_tys.keys().copied().filter(|l| *l < d).max() {
            let mut vars = self.vars_of_fact(last);
            for _ in 0..2 {
                let mut more = vars.clone();
                for f in &self.f.scope.facts {
                    let l = f.lvl.0;
                    if l < d {
                        let vs = self.vars_of_fact(l);
                        if !vs.is_disjoint(&vars) {
                            more.extend(vs);
                        }
                    }
                }
                vars = more;
            }
            let hide: Vec<u32> = self.f.scope.facts.iter().map(|f| f.lvl.0).filter(|l| *l < d && self.vars_of_fact(*l).is_disjoint(&vars)).collect();
            // nothing in scope is about the arm's test: it cannot contradict
            // anything (a test decidable on its own went to the test route)
            if self.f.scope.facts.iter().all(|f| f.lvl.0 == last || hide.contains(&f.lvl.0)) {
                let _ = self.split_records(&rec);
                return Ok(None);
            }
            self.f.scope.hidden.extend(hide);
        }
        let was = PROVER_DIV.with(|c| c.replace(PRUNE_DIV));
        let p = self.prove(ObligationKind::Refines, span, &empty, false);
        PROVER_DIV.with(|c| c.set(was));
        self.f.scope.hidden = hidden_before;
        let p = p?;
        if trace_level() >= 3 && std::env::var("SANDBLASTER_TRACE_LOCKSTEP_FN").is_ok_and(|x| x.split(',').any(|y| self.f.name.contains(y))) {
            let d = self.depth();
            let arm = self.f.scope.fact_tys.keys().copied().filter(|l| *l < d).max().and_then(|l| self.f.scope.fact_tys.get(&l).map(|t| self.surface(&shift(t, (d - l) as i64))));
            eprintln!("    prune {}: {}", if self.records_proven_since(&rec) { "closed" } else { "open" }, arm.unwrap_or_default().chars().take(300).collect::<String>());
        }
        if self.records_proven_since(&rec) && !super::tm::has_erased(&p) {
            stat(|s| s.pruned += 1);
            // the check's own record is not an obligation of the result
            let _ = self.split_records(&rec);
            return Ok(Some(p));
        }
        let _ = self.split_records(&rec);
        Ok(None)
    }

    /// [`Elab::ls_prune`] for an arm whose path equation is a `bool` test
    /// `e : Eq(Bool, b, c)` (`c` a literal): `b` has the other value by the
    /// prover (a goal it states directly, not a search for `Empty`), and
    /// the two values give `false = true`.
    fn ls_prune_test(&mut self, span: Span) -> R<Option<Tm>> {
        let d = self.depth();
        let Some(l) = self.f.scope.fact_tys.keys().copied().filter(|l| *l < d).max() else { return Ok(None) };
        let ft = shift(&self.f.scope.fact_tys[&l], (d - l) as i64);
        let Term::Eq { ty, lhs: b, rhs: c } = &*ft else { return Ok(None) };
        let Term::Ind { ind, .. } = &**ty else { return Ok(None) };
        if *ind != self.p.bool_ {
            return Ok(None);
        }
        let Term::Ctor { ctor: cv, .. } = &**c else { return Ok(None) };
        let (ff, tt) = (mk::ctor(self.p.bool_, 0, vec![], vec![]), mk::ctor(self.p.bool_, 1, vec![], vec![]));
        let other = if *cv == 0 { tt.clone() } else { ff.clone() };
        let goal = mk::eq(ty.clone(), self.zeta_all(b), other);
        let rec = self.save_records();
        let hints = self.push_spelled_facts();
        let was = PROVER_DIV.with(|x| x.replace(PRUNE_DIV));
        let p = self.prove(ObligationKind::Refines, span, &goal, true);
        PROVER_DIV.with(|x| x.set(was));
        self.f.scope.hint_facts.truncate(hints);
        let p = p?;
        if !self.records_proven_since(&rec) || super::tm::has_erased(&p) {
            let _ = self.split_records(&rec);
            return Ok(None);
        }
        let _ = self.split_records(&rec);
        let e = mk::apps(mk::global(self.p.g("eq::promote")), [(Rel::Rel, ty.clone()), (Rel::Rel, b.clone()), (Rel::Rel, c.clone()), (Rel::Irr, mk::var(d - 1 - l))]);
        let sym = |x: &Tm, y: &Tm, pf: Tm| mk::apps(mk::global(self.p.g("eq::sym")), [(Rel::Rel, ty.clone()), (Rel::Rel, x.clone()), (Rel::Rel, y.clone()), (Rel::Rel, pf)]);
        // false = b = true
        let (to_false, to_true) = if *cv == 0 { (sym(b, &ff, e), p) } else { (sym(b, &ff, p), e) };
        let ft_eq = mk::apps(mk::global(self.p.g("eq::trans")), [(Rel::Rel, ty.clone()), (Rel::Rel, ff.clone()), (Rel::Rel, b.clone()), (Rel::Rel, tt.clone()), (Rel::Rel, to_false), (Rel::Rel, to_true)]);
        Ok(Some(mk::app(mk::global(self.p.g("bool::false_ne_true")), ft_eq)))
    }

    /// The levels of the variables a fact (at level `l`) mentions, through
    /// the values of the `let`s it mentions (one level).
    fn vars_of_fact(&self, l: u32) -> std::collections::BTreeSet<u32> {
        let mut out = std::collections::BTreeSet::new();
        let Some(t) = self.f.scope.fact_tys.get(&l) else { return out };
        let mut todo: Vec<(Tm, u32, u32)> = vec![(t.clone(), l, 1)];
        while let Some((t, at, fuel)) = todo.pop() {
            super::tm::any_node_depth(&t, &mut |n, b| {
                if let Term::Var(sandblaster_kernel::term::Idx(i)) = n
                    && *i >= b
                    && i - b < at
                {
                    let lvl = at - 1 - (i - b);
                    if out.insert(lvl)
                        && fuel > 0
                        && let Some(v) = self.let_value(lvl)
                    {
                        todo.push((v, lvl, fuel - 1));
                    }
                }
                false
            });
        }
        out
    }

    /// Meets the two sides of `Eq(ty, l, r)` (see the module docs): a proof,
    /// or the deepest step that differs. `atoms`: whether the whole equation
    /// may go to the prover when nothing decomposes it.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn meet(&mut self, ty: &Tm, l: &Tm, r: &Tm, span: Span, fuel: u32, depth: u32, atoms: bool) -> R<Met> {
        let goal = mk::eq(ty.clone(), l.clone(), r.clone());
        if depth > MAX_DEPTH || !charge(STEP_COST) {
            return Ok(Err(self.divergence(&goal, depth, "")));
        }
        // the memo: the same equation in the same context
        let key = (Rc::as_ptr(&self.f.scope.ctx.entries) as usize, self.f.scope.facts.len(), super::tm::fingerprint(&goal));
        let seen: Vec<(Tm, Option<Tm>)> = with_state(|s| s.memo.get(&key).map(|v| v.iter().map(|(g, _, r)| (g.clone(), r.clone())).collect())).flatten().unwrap_or_default();
        if let Some(hit) = seen.into_iter().find(|(g, _)| Rc::ptr_eq(g, &goal) || self.env.alpha_eq_relevant(g, &goal, &|a, b| a == b)).map(|(_, r)| r) {
            stat(|s| s.memo_hits += 1);
            return Ok(match hit {
                Some(p) => Ok(p),
                None => Err(self.divergence(&goal, depth, "(seen before)")),
            });
        }
        let deep = trace_level() >= 2 && std::env::var("SANDBLASTER_TRACE_LOCKSTEP_FN").is_ok_and(|f| f.split(',').any(|x| self.f.name.contains(x)));
        if deep {
            eprintln!("{:w$}meet[{depth}]: {}", "", self.surface(&goal).chars().take(600).collect::<String>(), w = 2 * depth as usize);
        }
        // the same equation in the same context, already being met: a cycle
        let ctx_id = Rc::as_ptr(&self.f.scope.ctx.entries) as usize;
        let on_stack: Vec<Tm> = with_state(|s| s.stack.iter().filter(|(c, _)| *c == ctx_id).map(|(_, g)| g.clone()).collect()).unwrap_or_default();
        if on_stack.iter().any(|g| Rc::ptr_eq(g, &goal) || self.env.alpha_eq_relevant(g, &goal, &|a, b| a == b)) {
            return Ok(Err(self.divergence(&goal, depth, "")));
        }
        with_state(|s| s.stack.push((ctx_id, goal.clone())));
        let r0 = self.meet_uncached(ty, l, r, &goal, span, fuel, depth, atoms);
        with_state(|s| {
            s.stack.pop();
        });
        let r0 = r0?;
        if deep {
            eprintln!("{:w$}  -> {}", "", if r0.is_ok() { "met" } else { "differs" }, w = 2 * depth as usize);
        }
        let ctx = self.f.scope.ctx.entries.clone();
        let res = r0.as_ref().ok().cloned();
        with_state(|s| s.memo.entry(key).or_default().push((goal.clone(), ctx, res)));
        Ok(r0)
    }

    #[allow(clippy::too_many_arguments)]
    fn meet_uncached(&mut self, ty: &Tm, l: &Tm, r: &Tm, goal: &Tm, span: Span, fuel: u32, depth: u32, atoms: bool) -> R<Met> {
        // 1. conversion
        if self.env.alpha_eq_relevant(l, r, &|a, b| a == b) || self.convertible(l, r, 200_000) {
            return Ok(Ok(mk::refl(ty.clone(), l.clone())));
        }
        let mut best: Option<Divergence> = None;
        let mut split_tried = false;
        // 2. a side that is a `let`-bound choice (a variable, which no
        // structure meets): the code's first
        for left in [true, false] {
            let side = if left { l } else { r };
            if let Some((val, f)) = self.choice_at_head(side, false) {
                split_tried = true;
                let other = if left { r } else { l };
                match self.split_choice(ty, &val, &f, other, left, span, fuel, depth)? {
                    Ok(p) => return Ok(Ok(p)),
                    Err(d) => {
                        best = deeper(best, d);
                        break;
                    }
                }
            }
        }
        // 2b. a side that is a `let`-bound variable of another value (a
        // call, arithmetic): its value (by conversion, the `let` is in scope)
        {
            let (zl, zr) = (self.zeta_head(l), self.zeta_head(r));
            let changed = !Rc::ptr_eq(&zl, l) || !Rc::ptr_eq(&zr, r);
            if changed && !split_tried {
                return self.meet(ty, &zl, &zr, span, fuel, depth + 1, atoms);
            }
        }
        // 3. structure (before splitting a match at a side's head: a fact
        // about the code's call is stated through the view's match on it)
        match self.fact_head(ty, l, r, span, fuel, depth)? {
            Some(Ok(p)) => return Ok(Ok(p)),
            Some(Err(d)) => best = deeper(best, d),
            None => {}
        }
        match self.same_head(ty, l, r, span, fuel, depth)? {
            Some(Ok(p)) => return Ok(Ok(p)),
            Some(Err(d)) => best = deeper(best, d),
            None => {}
        }
        match self.ctor_fields(ty, l, r, span, fuel, depth)? {
            Some(Ok(p)) => return Ok(Ok(p)),
            Some(Err(d)) => best = deeper(best, d),
            None => {}
        }
        // 4. a `let`-bound choice inside a side (a match of the view on it
        // would lose its value), a match at a side's head, a match inside
        for left in [true, false] {
            if split_tried {
                break;
            }
            let side = if left { l } else { r };
            if let Some((val, f)) = self.choice_inside(side, true) {
                let other = if left { r } else { l };
                match self.split_choice(ty, &val, &f, other, left, span, fuel, depth)? {
                    Ok(p) => return Ok(Ok(p)),
                    Err(d) => {
                        best = deeper(best, d);
                        break;
                    }
                }
            }
        }
        for left in [true, false] {
            let side = if left { l } else { r };
            if let Some((val, f)) = self.choice_at_head(side, true) {
                let other = if left { r } else { l };
                match self.split_choice(ty, &val, &f, other, left, span, fuel, depth)? {
                    Ok(p) => return Ok(Ok(p)),
                    Err(d) => {
                        best = deeper(best, d);
                        break;
                    }
                }
            }
        }
        for left in [true, false] {
            let side = if left { l } else { r };
            if let Some((val, f)) = self.choice_inside(side, false) {
                let other = if left { r } else { l };
                match self.split_choice(ty, &val, &f, other, left, span, fuel, depth)? {
                    Ok(p) => return Ok(Ok(p)),
                    Err(d) => {
                        best = deeper(best, d);
                        break;
                    }
                }
            }
        }
        // 5. one step of a non-recursive spec function heading a side (the
        // target's side first)
        if fuel > 0 {
            for left in [false, true] {
                let side = if left { l } else { r };
                let other = if left { r } else { l };
                let (head, args) = super::items::spine(side);
                let Term::Global(f) = &*head else { continue };
                let f = *f;
                if !self.lockstep_target(f) || args.is_empty() || self.env.global_arity(f) != Some(args.len() as u32) || (self.env.global_opaque(f) == Some(true) && !self.is_model_fn(f)) {
                    continue;
                }
                let body = self.env.global_body(f).expect("body");
                if super::tm::any_node(&body, &mut |n| matches!(n, Term::Global(h) if *h == f)) {
                    continue;
                }
                let rec = self.save_records();
                match self.ls_step(ty, other, side, f, &args, left, span, fuel - 1, depth + 1)? {
                    Ok(p) if self.records_proven_since(&rec) => return Ok(Ok(p)),
                    Ok(_) => {
                        let _ = self.split_records(&rec);
                    }
                    Err(d) => {
                        let _ = self.split_records(&rec);
                        best = deeper(best, d);
                    }
                }
            }
        }
        // 6. an atom
        if !atoms {
            return Ok(Err(best.unwrap_or_else(|| self.divergence(goal, depth, ""))));
        }
        match self.atom(goal, span, depth)? {
            Ok(p) => Ok(Ok(p)),
            Err(d) => Ok(Err(deeper(best, d).unwrap())),
        }
    }

    /// The prover on an equation no rule decomposes. Each call of the code
    /// the equation mentions that a fact of the code relates to the target
    /// (a callee's refinement `α(g(ā)) = m(b̄)`, an induction hypothesis) is
    /// first generalized: a fresh value known only through that fact, as
    /// the callee is known through its contract (the code's body is not
    /// unfolded into the atom). What is left for the prover relates the
    /// code's operations on those values to the target's — what the
    /// bridges state. The proof is `(λv. λh. p) g(ā) fact`.
    fn atom(&mut self, goal: &Tm, span: Span, depth: u32) -> R<Met> {
        if !charge(ATOM_COST) {
            return Ok(Err(self.divergence(goal, depth, "")));
        }
        let facts = self.code_facts();
        let r = self.atom_gen(goal, &facts, span, depth)?;
        if r.is_ok() || !self.generalizes(goal, &facts) {
            return Ok(r);
        }
        // the plain equation (a fact may be needed as it stands)
        self.atom_plain(goal, span, depth)
    }

    /// Whether some fact's call occurs in `goal` ([`Elab::atom`]).
    fn generalizes(&self, goal: &Tm, facts: &[(Tm, Tm)]) -> bool {
        facts.iter().any(|(fty, _)| matches!(&**fty, Term::Eq { lhs, .. } if code_call(&under_view(lhs)) && super::tm::abstract_syntactic(&self.env, goal, &under_view(lhs)).is_some()))
    }

    /// [`Elab::atom`]: generalizes the first fact's call that occurs in
    /// `goal`, then the rest; the prover at the end.
    fn atom_gen(&mut self, goal: &Tm, facts: &[(Tm, Tm)], span: Span, depth: u32) -> R<Met> {
        let Some(k) = facts.iter().position(|(fty, _)| matches!(&**fty, Term::Eq { lhs, .. } if code_call(&under_view(lhs)) && super::tm::abstract_syntactic(&self.env, goal, &under_view(lhs)).is_some())) else {
            return self.atom_plain(goal, span, depth);
        };
        let (fty, fpf) = facts[k].clone();
        let Term::Eq { ty: a, lhs: x, rhs: y } = &*fty else { unreachable!() };
        let c = under_view(x);
        let mut b = sandblaster_kernel::value::Budget { steps: self.opts.goal_budget };
        let Ok(cv) = self.env.infer(&self.f.scope.ctx, &c, &mut b) else { return self.atom_plain(goal, span, depth) };
        let c_ty = self.quote(&cv, None);
        let body = super::tm::abstract_syntactic(&self.env, goal, &c).expect("occurs");
        let x_v = super::tm::abstract_syntactic(&self.env, x, &c).expect("occurs");
        // the target's call too, when the equation mentions it: a value `w`
        // known only as the code's (so its body is not unfolded either)
        let y1 = shift(y, 1);
        let body_w = super::tm::abstract_syntactic(&self.env, &body, &y1);
        let saved = self.f.scope.clone();
        let r = (|| -> R<Met> {
            self.push("v", Rel::Rel, &c_ty, None)?;
            let (goal2, fact2, extra) = match &body_w {
                Some(bw) => {
                    self.push("w", Rel::Rel, &shift(a, 1), None)?;
                    (bw.clone(), mk::eq(shift(a, 2), shift(&x_v, 1), mk::var(0)), 1u32)
                }
                None => (body.clone(), mk::eq(shift(a, 1), x_v.clone(), y1.clone()), 0u32),
            };
            self.push_fact_rel("h_v", Rel::Irr, &fact2, None, crate::prover::FactOrigin::LemmaHyp, span)?;
            let k2 = 2 + extra as i64;
            let rest: Vec<(Tm, Tm)> = facts.iter().enumerate().filter(|(j, _)| *j != k).map(|(_, (t, p))| (shift(t, k2), shift(p, k2))).collect();
            let r = self.atom_gen(&shift(&goal2, 1), &rest, span, depth)?;
            Ok(r.map(|p| {
                let with_h = mk::lam("h_v", Rel::Irr, fact2.clone(), p);
                if extra == 1 { mk::lam("w", Rel::Rel, shift(a, 1), with_h) } else { with_h }
            }))
        })();
        self.f.scope = saved;
        Ok(r?.map(|p| {
            let f = mk::lam("v", Rel::Rel, c_ty.clone(), p);
            let applied = mk::app(f, c.clone());
            let applied = if body_w.is_some() { mk::app(applied, y.clone()) } else { applied };
            mk::app_irr(applied, fpf.clone())
        }))
    }

    /// The equational facts of the code in scope, `(type, proof)` at the
    /// current depth: the callees' refinements at their calls and the
    /// induction hypotheses.
    fn code_facts(&self) -> Vec<(Tm, Tm)> {
        let d = self.depth();
        let mut out: Vec<(Tm, Tm)> = Vec::new();
        let mut seen: Vec<u32> = Vec::new();
        for (lvl, ty0) in &self.f.scope.ref_facts {
            if *lvl < d && !self.f.scope.hidden.contains(lvl) && !seen.contains(lvl) {
                seen.push(*lvl);
                out.push((shift(ty0, (d - lvl) as i64), mk::var(d - 1 - lvl)));
            }
        }
        for f in &self.f.scope.facts {
            let l = f.lvl.0;
            if f.origin != crate::prover::FactOrigin::InductionHyp || l >= d || self.f.scope.hidden.contains(&l) || seen.contains(&l) {
                continue;
            }
            if let Some(t) = self.f.scope.fact_tys.get(&l) {
                seen.push(l);
                out.push((shift(t, (d - l) as i64), mk::var(d - 1 - l)));
            }
        }
        out
    }

    fn atom_plain(&mut self, goal: &Tm, span: Span, depth: u32) -> R<Met> {
        stat(|s| s.atoms += 1);
        let deep = trace_level() >= 2 && std::env::var("SANDBLASTER_TRACE_LOCKSTEP_FN").is_ok_and(|f| f.split(',').any(|x| self.f.name.contains(x)));
        let rec = self.save_records();
        // the callees' refinements at their calls in the equation (the walk
        // keeps them as `let`s, not as facts of the prover): given to the
        // prover as facts of this slot
        let hints_before = self.f.scope.hint_facts.len();
        for (ty, pf) in self.ref_facts_about(goal) {
            let d = self.depth();
            self.f.scope.hint_facts.push(super::scope::HintFact { ty: super::scope::Val::new(ty, d), proof: super::scope::Val::new(pf, d), name: "h_ref", origin: crate::prover::FactOrigin::LemmaHyp });
        }
        let _ = self.push_spelled_facts();
        let was = PROVER_DIV.with(|c| c.replace(ATOM_DIV));
        let p = self.prove_relevant(ObligationKind::Refines, span, goal);
        PROVER_DIV.with(|c| c.set(was));
        self.f.scope.hint_facts.truncate(hints_before);
        let p = p?;
        if self.records_proven_since(&rec) {
            return Ok(Ok(p));
        }
        stat(|s| s.atoms_failed += 1);
        let taken = self.split_records(&rec);
        if deep {
            eprintln!("    atom failed: {}", self.surface(goal).chars().take(800).collect::<String>());
            for d in &taken.diags {
                if let Some(g) = &d.goal {
                    eprintln!("      {}", g.chars().take(3000).collect::<String>().replace('\n', "\n      "));
                }
                for (_, n) in d.notes.iter().take(6) {
                    eprintln!("      note: {}", n.chars().take(400).collect::<String>());
                }
            }
        }
        let why: Vec<String> = taken.diags.iter().filter_map(|d| d.notes.iter().find_map(|(_, n)| n.strip_prefix("stuck: ").map(|s| s.to_string()))).take(2).collect();
        let extra = if why.is_empty() { String::new() } else { format!("\n    stuck: {}", why.join("; ")) };
        Ok(Err(self.divergence(goal, depth, &extra)))
    }

    /// The callee refinement facts in scope (`Scope::ref_facts`) about the
    /// calls an equation mentions — directly or through the values of the
    /// `let`s it mentions — as relevant facts `(type, proof)` at the current
    /// depth.
    fn ref_facts_about(&self, goal: &Tm) -> Vec<(Tm, Tm)> {
        let d = self.depth();
        if self.f.scope.ref_facts.is_empty() {
            return vec![];
        }
        // the globals the goal mentions, through its `let`s (two levels)
        let mut heads: std::collections::HashSet<GlobalId> = std::collections::HashSet::new();
        let mut todo: Vec<(Tm, u32)> = vec![(goal.clone(), 2)];
        while let Some((t, lvl_fuel)) = todo.pop() {
            super::tm::any_node_depth(&t, &mut |n, b| {
                match n {
                    Term::Global(g) => {
                        heads.insert(*g);
                    }
                    Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= b && lvl_fuel > 0 => {
                        let i = i - b;
                        if i < d
                            && let Some(v) = self.let_value(d - 1 - i)
                        {
                            todo.push((shift(&v, (i + 1) as i64), lvl_fuel - 1));
                        }
                    }
                    _ => {}
                }
                false
            });
        }
        let mut out = Vec::new();
        for (lvl, ty0) in &self.f.scope.ref_facts {
            if *lvl >= d || self.f.scope.hidden.contains(lvl) {
                continue;
            }
            let ty = shift(ty0, (d - lvl) as i64);
            let Term::Eq { ty: a, lhs, rhs } = &*ty else { continue };
            let (head, _) = super::items::spine(&under_view(lhs));
            if !matches!(&*head, Term::Global(g) if heads.contains(g)) {
                continue;
            }
            let pf = mk::apps(mk::global(self.p.g("eq::promote")), [(Rel::Rel, a.clone()), (Rel::Rel, lhs.clone()), (Rel::Rel, rhs.clone()), (Rel::Irr, mk::var(d - 1 - lvl))]);
            out.push((ty.clone(), pf));
        }
        out
    }

    /// The report of a step that differs: the walk's position, the
    /// equation, and the path facts the lockstep added.
    fn divergence(&self, goal: &Tm, depth: u32, extra: &str) -> Divergence {
        let base = with_state(|s| s.base).unwrap_or(0);
        let d = self.depth();
        let mut facts = Vec::new();
        let mut lvls: Vec<u32> = self.f.scope.fact_tys.keys().copied().filter(|l| *l >= base && *l < d).collect();
        lvls.sort();
        for l in lvls {
            if let Some(t) = self.f.scope.fact_tys.get(&l) {
                facts.push(self.surface(&shift(t, (d - l) as i64)));
            }
        }
        let mut text = String::new();
        for c in crumbs() {
            text.push_str(&format!("\n    {c}"));
        }
        text.push_str(&format!("\n    code and target differ at: {}", self.surface(goal)));
        for f in facts.iter().take(12) {
            text.push_str(&format!("\n      where {f}"));
        }
        text.push_str(extra);
        Divergence { depth, text }
    }

    /// Whether two terms at the current depth are convertible (bounded).
    fn convertible(&self, a: &Tm, b: &Tm, steps: u64) -> bool {
        let (Ok(av), Ok(bv)) = (self.eval(a), self.eval(b)) else { return false };
        let mut bud = sandblaster_kernel::value::Budget { steps: self.opts.goal_budget.min(steps) };
        self.env.conv(sandblaster_kernel::term::Lvl(self.depth()), &av, &bv, &mut bud).unwrap_or(false)
    }

    /// `t` with its head `let`-bound variables replaced by their values (as
    /// long as the head is such a variable).
    fn zeta_head(&self, t: &Tm) -> Tm {
        let d = self.depth();
        let mut cur = t.clone();
        for _ in 0..8 {
            let Term::Var(sandblaster_kernel::term::Idx(i)) = &*cur else { break };
            if *i >= d {
                break;
            }
            let lvl = d - 1 - i;
            match self.let_value(lvl) {
                Some(v) => cur = shift(&v, (d - lvl) as i64),
                None => break,
            }
        }
        cur
    }

    /// `t` (a term at the current depth) with every relevant `let`-bound
    /// variable replaced by its value, recursively (a few rounds): the
    /// prover reads a `bool` test through its name only if it is spelled
    /// out (`left == true` is `index < width / 2`).
    fn zeta_all(&self, t: &Tm) -> Tm {
        let d = self.depth();
        let mut cur = t.clone();
        for _ in 0..4 {
            let mut changed = false;
            let next = super::tm::map_post(&cur, 0, &mut |n, b| {
                if let Term::Var(sandblaster_kernel::term::Idx(i)) = &*n
                    && *i >= b
                    && i - b < d
                {
                    let lvl = d - 1 - (i - b);
                    if let Some(v) = self.let_value(lvl) {
                        changed = true;
                        return Some(shift(&v, (d - lvl + b) as i64));
                    }
                }
                Some(n)
            })
            .unwrap_or(cur.clone());
            cur = next;
            if !changed {
                break;
            }
        }
        cur
    }

    /// The facts in scope whose statements mention `let`-bound variables,
    /// spelled out ([`Elab::zeta_all`]) as hint facts of the next proof slot
    /// (their proofs are the facts themselves: the statements convert).
    /// Returns the previous number of hint facts (to truncate back to).
    fn push_spelled_facts(&mut self) -> usize {
        let before = self.f.scope.hint_facts.len();
        let d = self.depth();
        let lvls: Vec<u32> = self.f.scope.fact_tys.keys().copied().filter(|l| *l < d && !self.f.scope.hidden.contains(l)).collect();
        for l in lvls {
            let t = shift(&self.f.scope.fact_tys[&l], (d - l) as i64);
            let z = self.zeta_all(&t);
            if Rc::ptr_eq(&z, &t) || self.env.alpha_eq_relevant(&z, &t, &|a, b| a == b) {
                continue;
            }
            let rel_ok = matches!(&*z, Term::Eq { .. });
            if !rel_ok {
                continue;
            }
            let Term::Eq { ty: a, lhs, rhs } = &*z else { continue };
            let pf = mk::apps(mk::global(self.p.g("eq::promote")), [(Rel::Rel, a.clone()), (Rel::Rel, lhs.clone()), (Rel::Rel, rhs.clone()), (Rel::Irr, mk::var(d - 1 - l))]);
            self.f.scope.hint_facts.push(super::scope::HintFact { ty: super::scope::Val::new(z.clone(), d), proof: super::scope::Val::new(pf, d), name: "h_let", origin: crate::prover::FactOrigin::PathCond });
        }
        before
    }

    /// The value term of the relevant `let` at level `lvl` (at the depth of
    /// the level), if the binder there is that `let`.
    fn let_value(&self, lvl: u32) -> Option<Tm> {
        let (_, val, v0) = self.f.scope.let_tms.get(&lvl)?;
        matches!(self.f.scope.ctx.entries.get(lvl as usize).and_then(|e| e.def.as_ref()), Some(sandblaster_kernel::value::Arg::Rel(v)) if Rc::ptr_eq(v, v0)).then(|| val.clone())
    }

    /// Whether `a` and `b` (terms at the current depth) are the same term up
    /// to the `let`s at their heads and binder names, or convertible when
    /// their heads agree.
    fn same_term(&self, a: &Tm, b: &Tm) -> bool {
        if self.env.alpha_eq_relevant(a, b, &|x, y| x == y) {
            return true;
        }
        let (za, zb) = (self.zeta_head(a), self.zeta_head(b));
        if self.env.alpha_eq_relevant(&za, &zb, &|x, y| x == y) {
            return true;
        }
        let (ha, _) = super::items::spine(&za);
        let (hb, _) = super::items::spine(&zb);
        matches!((&*ha, &*hb), (Term::Global(x), Term::Global(y)) if x == y) && self.convertible(&za, &zb, 100_000)
    }

    /// Rule 3a: a fact `Eq(T, X, g(c̄))` in scope with `X` the equation's
    /// left side (a callee's refinement at its call, an induction
    /// hypothesis): `trans(fact, meet(g(c̄), r))`; or its mirror, a fact
    /// `Eq(T, g(c̄), Y)` with `Y` the right side. `None` when no fact
    /// applies.
    fn fact_head(&mut self, ty: &Tm, l: &Tm, r: &Tm, span: Span, fuel: u32, depth: u32) -> R<Option<Met>> {
        let d = self.depth();
        let mut sources: Vec<(u32, Tm)> = self.f.scope.facts.iter().filter_map(|f| self.f.scope.fact_tys.get(&f.lvl.0).map(|t| (f.lvl.0, t.clone()))).collect();
        for rf in &self.f.scope.ref_facts {
            if !sources.iter().any(|(l, _)| *l == rf.0) {
                sources.push(rf.clone());
            }
        }
        // candidates: (level, the fact's other side, fact is about the left)
        let mut cands: Vec<(u32, Tm, bool)> = Vec::new();
        for (lvl, ft) in sources {
            if lvl >= d || self.f.scope.hidden.contains(&lvl) {
                continue;
            }
            let ft = shift(&ft, (d - lvl) as i64);
            let Term::Eq { lhs: fl, rhs: fr, ty: fty } = &*ft else { continue };
            if trace_level() >= 3 {
                eprintln!("      fact {lvl}: {} (type {})", self.surface(&ft).chars().take(300).collect::<String>(), if self.env.alpha_eq_relevant(fty, ty, &|a, b| a == b) { "same" } else { "differs" });
            }
            if !self.env.alpha_eq_relevant(fty, ty, &|a, b| a == b) && !self.convertible(fty, ty, 10_000) {
                continue;
            }
            let (frh, _) = super::items::spine(fr);
            if matches!(&*frh, Term::Global(_)) && !self.env.alpha_eq_relevant(fr, r, &|a, b| a == b) && self.same_term(fl, l) {
                cands.push((lvl, fr.clone(), true));
                continue;
            }
            let (flh, _) = super::items::spine(fl);
            if matches!(&*flh, Term::Global(_)) && !self.env.alpha_eq_relevant(fl, l, &|a, b| a == b) && self.same_term(fr, r) {
                cands.push((lvl, fl.clone(), false));
            }
        }
        if cands.is_empty() {
            return Ok(None);
        }
        let mut best: Option<Divergence> = None;
        for (lvl, mid, about_left) in cands {
            let rec = self.save_records();
            let fact = |el: &Self, a: &Tm, b: &Tm| mk::apps(mk::global(el.p.g("eq::promote")), [(Rel::Rel, ty.clone()), (Rel::Rel, a.clone()), (Rel::Rel, b.clone()), (Rel::Irr, mk::var(d - 1 - lvl))]);
            if trace_level() >= 2 && std::env::var("SANDBLASTER_TRACE_LOCKSTEP_FN").is_ok_and(|f| f.split(',').any(|x| self.f.name.contains(x))) {
                eprintln!("{:w$}  by fact {lvl} ({}): mid {}", "", if about_left { "code side" } else { "target side" }, self.surface(&mid).chars().take(300).collect::<String>(), w = 2 * depth as usize);
            }
            let r1 = if about_left {
                // fact : X = mid (X ≡ l); mid = r by the meet
                crumb_push(format!("the code's call, by its fact: {}", self.surface(&mid)));
                let m = self.meet(ty, &mid, r, span, fuel, depth + 1, true)?;
                crumb_pop();
                m.map(|q| mk::apps(mk::global(self.p.g("eq::trans")), [(Rel::Rel, ty.clone()), (Rel::Rel, l.clone()), (Rel::Rel, mid.clone()), (Rel::Rel, r.clone()), (Rel::Rel, fact(self, l, &mid)), (Rel::Rel, q)]))
            } else {
                // fact : mid = Y (Y ≡ r); l = mid by the meet
                let m = self.meet(ty, l, &mid, span, fuel, depth + 1, true)?;
                m.map(|q| mk::apps(mk::global(self.p.g("eq::trans")), [(Rel::Rel, ty.clone()), (Rel::Rel, l.clone()), (Rel::Rel, mid.clone()), (Rel::Rel, r.clone()), (Rel::Rel, q), (Rel::Rel, fact(self, &mid, r))]))
            };
            match r1 {
                Ok(p) if self.records_proven_since(&rec) => return Ok(Some(Ok(p))),
                Ok(_) => {
                    let _ = self.split_records(&rec);
                }
                Err(dv) => {
                    let _ = self.split_records(&rec);
                    best = deeper(best, dv);
                }
            }
        }
        Ok(Some(Err(best.expect("a candidate"))))
    }

    /// Rule 3b: `Eq(T, g(ā), g(b̄))` for a global `g`: [`Elab::dep_congruence`]
    /// from `refl`, each argument met.
    fn same_head(&mut self, ty: &Tm, l: &Tm, r: &Tm, span: Span, fuel: u32, depth: u32) -> R<Option<Met>> {
        let (lh, la) = super::items::spine(l);
        let (rh, ra) = super::items::spine(r);
        let (Term::Global(g), Term::Global(h)) = (&*lh, &*rh) else { return Ok(None) };
        if g != h || la.is_empty() || la.len() != ra.len() {
            return Ok(None);
        }
        let Some(rels) = self.env.global_param_rels(*g) else { return Ok(None) };
        if rels.len() != la.len() {
            return Ok(None);
        }
        let rec = self.save_records();
        let refl = mk::refl(ty.clone(), l.clone());
        let name = self.env.global_name(*g).map(|n| n.to_string()).unwrap_or_default();
        match self.dep_congruence(ty, l, *g, &name, &rels, &la, &ra, refl, span, fuel, depth)? {
            Ok(p) if self.records_proven_since(&rec) => Ok(Some(Ok(p))),
            Ok(_) => {
                let _ = self.split_records(&rec);
                Ok(Some(Err(Divergence { depth, text: "an argument's obligation is unproven".into() })))
            }
            Err(d) => {
                let _ = self.split_records(&rec);
                Ok(Some(Err(d)))
            }
        }
    }

    /// From `p : Eq(T, L, S(ā))` (`ā` the whole spine, irrelevant proof
    /// arguments included) a proof of `Eq(T, L, S(b̄))`: for each relevant
    /// position `i` with `aᵢ ≠ bᵢ`, `e : Eq(Aᵢ, aᵢ, bᵢ)` by [`Elab::meet`]
    /// and
    ///
    /// ```text
    /// transport(Aᵢ, aᵢ, bᵢ, e, y. Π(e' :Irr Eq(Aᵢ, aᵢ, y)). Eq(T, L, S(…, y, H(y, e'), …)), λe'. p) e
    /// ```
    ///
    /// where every irrelevant argument `H` whose binder type mentions
    /// position `i` is the current proof transported along `e'` (so the
    /// motive is well typed; conversion ignores irrelevant arguments, so the
    /// instances are the goals).
    #[allow(clippy::too_many_arguments)]
    fn dep_congruence(&mut self, ty: &Tm, lhs: &Tm, s: GlobalId, name: &str, rels: &[Rel], as_: &[Tm], bs: &[Tm], p: Tm, span: Span, fuel: u32, depth: u32) -> R<Met> {
        let n = as_.len();
        // the binder types of `S`'s telescope (binder k over the k earlier ones)
        let mut doms: Vec<Tm> = Vec::new();
        let Some(mut t) = self.env.global_type(s) else { return Ok(Err(Divergence { depth, text: "no type".into() })) };
        for _ in 0..n {
            let next = match &*t {
                Term::Pi { dom, cod, .. } => {
                    doms.push(dom.clone());
                    cod.clone()
                }
                _ => return Ok(Err(Divergence { depth, text: format!("`{name}` is applied beyond its telescope") })),
            };
            t = next;
        }
        let mut cur: Vec<Tm> = as_.to_vec();
        let mut proof = p;
        for i in 0..n {
            if rels[i] != Rel::Rel || self.env.alpha_eq_relevant(&cur[i], &bs[i], &|a, b| a == b) {
                continue;
            }
            let a_ty = super::tm::subst_closed(&doms[i], &cur[..i]);
            crumb_push(format!("argument {} of `{name}`", i + 1));
            let e = self.meet(&a_ty, &cur[i], &bs[i], span, fuel, depth + 1, true)?;
            crumb_pop();
            let e = match e {
                Ok(e) => e,
                Err(d) => return Ok(Err(d)),
            };
            // the motive's spine at depth d + 2 (y = Var(1), e' = Var(0))
            let mut args2: Vec<Tm> = Vec::with_capacity(n);
            for k in 0..n {
                let a = if k == i {
                    mk::var(1)
                } else if rels[k] == Rel::Irr && k > i && mentions_var(&doms[k], (k - 1 - i) as u32) {
                    // H(y, e') = transport(Aᵢ, aᵢ, y, e', w. D_k[.., w, ..], h_k)
                    let mut wargs: Vec<Tm> = args2.iter().map(|x| shift(x, 1)).collect();
                    wargs[i] = mk::var(0);
                    let dk_w = super::tm::subst_closed(&doms[k], &wargs);
                    Rc::new(Term::Transport { ty: shift(&a_ty, 2), lhs: shift(&cur[i], 2), rhs: mk::var(1), eq: mk::var(0), motive: dk_w, val: shift(&cur[k], 2) })
                } else {
                    shift(&cur[k], 2)
                };
                args2.push(a);
            }
            let app2 = mk::apps(mk::global(s), args2.iter().zip(rels).map(|(a, r)| (*r, a.clone())));
            let eq_dom = mk::eq(shift(&a_ty, 1), shift(&cur[i], 1), mk::var(0));
            let motive = mk::pi("e", Rel::Irr, eq_dom, mk::eq(shift(ty, 2), shift(lhs, 2), app2));
            let val = mk::lam("e", Rel::Irr, mk::eq(a_ty.clone(), cur[i].clone(), cur[i].clone()), shift(&proof, 1));
            let tr: Tm = Rc::new(Term::Transport { ty: a_ty.clone(), lhs: cur[i].clone(), rhs: bs[i].clone(), eq: e.clone(), motive, val });
            proof = mk::app_irr(tr, e.clone());
            // the new spine: `bᵢ`, and the transported proofs at `(bᵢ, e)`
            let mut next = cur.clone();
            next[i] = bs[i].clone();
            for k in (i + 1)..n {
                if rels[k] == Rel::Irr && mentions_var(&doms[k], (k - 1 - i) as u32) {
                    let mut wargs: Vec<Tm> = next[..k].iter().map(|x| shift(x, 1)).collect();
                    wargs[i] = mk::var(0);
                    let dk_w = super::tm::subst_closed(&doms[k], &wargs);
                    next[k] = Rc::new(Term::Transport { ty: a_ty.clone(), lhs: cur[i].clone(), rhs: bs[i].clone(), eq: e.clone(), motive: dk_w, val: cur[k].clone() });
                }
            }
            cur = next;
        }
        Ok(Ok(proof))
    }

    /// Rule 3c: `Eq(T, L, R)` where `L` and `R` are (or evaluate to) the same
    /// constructor `C(ā)`, `C(b̄)` with relevant fields only: `cong` one field
    /// at a time, each field met.
    fn ctor_fields(&mut self, ty: &Tm, lhs: &Tm, rhs: &Tm, span: Span, fuel: u32, depth: u32) -> R<Option<Met>> {
        use sandblaster_kernel::value::{Arg, Value};
        // syntactically (the fields keep their `let`-bound choices): both
        // sides head-reduced, through `let`s at the head
        let l = crate::elab::tm::head_reduce(&self.zeta_head(lhs));
        let r = crate::elab::tm::head_reduce(&self.zeta_head(rhs));
        if let (Term::Ctor { ind: li, ctor: lc, params: lp, args: la }, Term::Ctor { ind: ri, ctor: rc, args: ra, .. }) = (&*l, &*r)
            && li == ri
            && lc == rc
            && la.len() == ra.len()
            && self.env.inductive_decl(*li).is_some_and(|d| d.ctors[*lc as usize].fields.iter().all(|f| f.1 == Rel::Rel))
        {
            let (ind, ctor, params, la, ra) = (*li, *lc, lp.clone(), la.clone(), ra.clone());
            return self.decompose_ctor(ty, ind, ctor, &params, &la, &ra, span, fuel, depth).map(Some);
        }
        // by value (not a sequence: element by element is never the step)
        let (th, _) = super::items::spine(ty);
        let buffer = matches!(&*th, Term::Global(g) if self.env.global_name(*g).is_some_and(|n| &*n == "Array" || &*n == "Slice"));
        if buffer || matches!(&**ty, Term::Ind { ind, .. } if *ind == self.p.list) || matches!(&**ty, Term::Sigma { .. }) {
            return Ok(None);
        }
        let (Ok(lv), Ok(rv)) = (self.eval(lhs), self.eval(rhs)) else { return Ok(None) };
        let (Value::Ctor { ind: li, ctor: lc, params: lp, args: la }, Value::Ctor { ind: ri, ctor: rc, args: ra, .. }) = (&*lv, &*rv) else { return Ok(None) };
        if li != ri || lc != rc || la.len() != ra.len() || la.iter().chain(ra.iter()).any(|a| !matches!(a, Arg::Rel(_))) {
            return Ok(None);
        }
        let quote_arg = |el: &Self, a: &Arg| match a {
            Arg::Rel(v) => el.quote(v, None),
            Arg::Irr(_) => mk::var(0),
        };
        let params: Vec<Tm> = lp.iter().map(|p| self.quote(p, None)).collect();
        let a_tms: Vec<Tm> = la.iter().map(|a| quote_arg(self, a)).collect();
        let b_tms: Vec<Tm> = ra.iter().map(|a| quote_arg(self, a)).collect();
        let (ind, ctor) = (*li, *lc);
        self.decompose_ctor(ty, ind, ctor, &params, &a_tms, &b_tms, span, fuel, depth).map(Some)
    }

    /// `Eq(T, C(ā), C(b̄))` by `cong` one field at a time, each field met.
    #[allow(clippy::too_many_arguments)]
    fn decompose_ctor(&mut self, ty: &Tm, ind: sandblaster_kernel::term::IndId, ctor: u32, params: &[Tm], a_tms: &[Tm], b_tms: &[Tm], span: Span, fuel: u32, depth: u32) -> R<Met> {
        let rec = self.save_records();
        let app = |xs: &[Tm]| mk::ctor(ind, ctor, params.to_vec(), xs.to_vec());
        let cname = self.env.inductive_decl(ind).map(|d| d.ctors[ctor as usize].name.to_string()).unwrap_or_default();
        let fnames: Vec<String> = self.env.inductive_decl(ind).map(|d| d.ctors[ctor as usize].fields.iter().map(|f| f.0.to_string()).collect()).unwrap_or_default();
        let mut cur = a_tms.to_vec();
        let mut proof = mk::refl(ty.clone(), app(&cur));
        for i in 0..cur.len() {
            if self.env.alpha_eq_relevant(&a_tms[i], &b_tms[i], &|a, b| a == b) {
                cur[i] = b_tms[i].clone();
                continue;
            }
            let mut b = sandblaster_kernel::value::Budget { steps: self.opts.goal_budget };
            let Ok(fv) = self.env.infer(&self.f.scope.ctx, &a_tms[i], &mut b) else {
                let _ = self.split_records(&rec);
                return Ok(Err(Divergence { depth, text: "a field's type".into() }));
            };
            let f_ty = self.quote(&fv, None);
            crumb_push(format!("field `{}` of `{cname}`", fnames.get(i).cloned().unwrap_or_else(|| i.to_string())));
            let e = self.meet(&f_ty, &a_tms[i], &b_tms[i], span, fuel, depth + 1, true)?;
            crumb_pop();
            let e = match e {
                Ok(e) => e,
                Err(d) => {
                    let _ = self.split_records(&rec);
                    return Ok(Err(d));
                }
            };
            let mut body_args: Vec<Tm> = cur.iter().map(|a| shift(a, 1)).collect();
            body_args[i] = mk::var(0);
            let body = mk::ctor(ind, ctor, params.iter().map(|p| shift(p, 1)).collect(), body_args);
            let f = mk::lam("y", Rel::Rel, f_ty.clone(), body);
            let before = app(&cur);
            let mut next = cur.clone();
            next[i] = b_tms[i].clone();
            let after = app(&next);
            let step = mk::apps(mk::global(self.p.g("eq::cong")), [(Rel::Rel, f_ty), (Rel::Rel, ty.clone()), (Rel::Rel, f), (Rel::Rel, a_tms[i].clone()), (Rel::Rel, b_tms[i].clone()), (Rel::Rel, e)]);
            proof = mk::apps(mk::global(self.p.g("eq::trans")), [(Rel::Rel, ty.clone()), (Rel::Rel, app(a_tms)), (Rel::Rel, before), (Rel::Rel, after), (Rel::Rel, proof), (Rel::Rel, step)]);
            cur = next;
        }
        if !self.records_proven_since(&rec) {
            let _ = self.split_records(&rec);
            return Ok(Err(Divergence { depth, text: "a field's obligation is unproven".into() }));
        }
        Ok(Ok(proof))
    }

    /// A choice at the head of `t`: a relevant `let`-bound variable whose
    /// value is a match, or a match itself — `(value, t abstracted over it)`
    /// (the abstraction at depth + 1, `Var(0)` the choice).
    fn choice_at_head(&self, t: &Tm, matches: bool) -> Option<(Tm, Tm)> {
        let d = self.depth();
        match &**t {
            Term::Var(sandblaster_kernel::term::Idx(i)) if *i < d && !matches => {
                let lvl = d - 1 - i;
                let val = self.let_value(lvl)?;
                is_choice(&val).then(|| (shift(&val, (d - lvl) as i64), mk::var(0)))
            }
            _ if matches && is_match(t) => Some((t.clone(), mk::var(0))),
            _ => None,
        }
    }

    /// The first choice inside `t` (not under a binder): a `let`-bound
    /// variable whose value is a match, or a match subterm.
    fn choice_inside(&self, t: &Tm, lets_only: bool) -> Option<(Tm, Tm)> {
        let d = self.depth();
        let mut found: Option<(Tm, Tm)> = None;
        let _ = super::tm::map_post(t, 0, &mut |n, b| {
            if found.is_some() || b != 0 {
                return Some(n);
            }
            match &*n {
                Term::Var(sandblaster_kernel::term::Idx(i)) if *i < d => {
                    let lvl = d - 1 - i;
                    if let Some(val) = self.let_value(lvl)
                        && is_choice(&val)
                    {
                        found = Some((shift(&val, (d - lvl) as i64), abstract_var(t, *i)));
                    }
                }
                _ if !lets_only && is_match(&n) => {
                    if let Some(f) = super::tm::abstract_syntactic(&self.env, t, &n) {
                        found = Some((n.clone(), f));
                    }
                }
                _ => {}
            }
            Some(n)
        });
        found
    }

    /// Walks the choice `val` (its tests split with their path equations),
    /// meeting `f[v]` with `other` at each outcome `v` (`left`: `f[·]` is the
    /// equation's left side).
    #[allow(clippy::too_many_arguments)]
    fn split_choice(&mut self, ty: &Tm, val: &Tm, f: &Tm, other: &Tm, left: bool, span: Span, fuel: u32, depth: u32) -> R<Met> {
        if !charge(SPLIT_COST) {
            let g = mk::eq(ty.clone(), shift(&super::tm::subst0(f, val), 0), other.clone());
            return Ok(Err(self.divergence(&g, depth, "")));
        }
        stat(|s| s.splits += 1);
        let rec = self.save_records();
        let saved = self.f.scope.clone();
        let mut g = ChoiceGoal { ty: ty.clone(), f: f.clone(), other: other.clone(), left, base: self.depth(), fuel, depth, span, failure: None };
        let walked = self.walk_body(val, &mut g);
        self.f.scope = saved;
        match walked {
            Ok(p) if self.records_proven_since(&rec) => Ok(Ok(p)),
            Ok(_) => {
                let _ = self.split_records(&rec);
                Ok(Err(g.failure.unwrap_or(Divergence { depth, text: "an obligation of a choice is unproven".into() })))
            }
            Err(e) if e.msg.starts_with("lockstep:") => {
                let _ = self.split_records(&rec);
                Ok(Err(g.failure.unwrap_or(Divergence { depth, text: "a branch differs".into() })))
            }
            Err(e) => {
                let _ = self.split_records(&rec);
                Ok(Err(Divergence { depth, text: format!("the walk of a choice failed: {}", e.msg) }))
            }
        }
    }

    /// The crumb of an arm: its path equation, in surface syntax.
    pub(super) fn ls_arm_crumb(&self) -> Option<String> {
        let d = self.depth();
        let lvl = d.checked_sub(1)?;
        let t = self.f.scope.fact_tys.get(&lvl)?;
        Some(format!("where {}", self.surface(&shift(t, 1))))
    }
}

/// `SANDBLASTER_TRACE_LOCKSTEP`: 1 prints each lockstep's outcome, 2 every
/// equation it meets.
fn trace_level() -> u32 {
    std::env::var("SANDBLASTER_TRACE_LOCKSTEP").ok().map(|v| v.parse().unwrap_or(1)).unwrap_or(0)
}

/// The deeper of two divergences (the first on a tie).
fn deeper(a: Option<Divergence>, b: Divergence) -> Option<Divergence> {
    match a {
        Some(a) if a.depth >= b.depth => Some(a),
        _ => Some(b),
    }
}

/// The side of a lockstep step ([`Elab::ls_step`]): the goal at a value `m`
/// of the walked body is `Eq(ty, m, other)` (`left`) or `Eq(ty, other, m)`,
/// `ty` and `other` at depth `base`.
struct SideGoal {
    ty: Tm,
    other: Tm,
    base: u32,
    span: Span,
    left: bool,
    fuel: u32,
    depth: u32,
    failure: Option<Divergence>,
}

impl<'a> WalkGoal<'a> for SideGoal {
    fn goal(&mut self, el: &mut Elab<'a>, m: &Tm) -> R<Tm> {
        let k = (el.depth() - self.base) as i64;
        Ok(if self.left { mk::eq(shift(&self.ty, k), m.clone(), shift(&self.other, k)) } else { mk::eq(shift(&self.ty, k), shift(&self.other, k), m.clone()) })
    }

    fn leaf(&mut self, el: &mut Elab<'a>, t: &Tm) -> R<Tm> {
        let k = (el.depth() - self.base) as i64;
        let (ty, o) = (shift(&self.ty, k), shift(&self.other, k));
        let (l, r) = if self.left { (t.clone(), o) } else { (o, t.clone()) };
        match el.meet(&ty, &l, &r, self.span, self.fuel, self.depth + 1, true)? {
            Ok(p) => Ok(p),
            Err(d) => {
                self.failure = deeper(self.failure.take(), d);
                Err(abort(self.span))
            }
        }
    }

    fn prune(&mut self, el: &mut Elab<'a>) -> R<Option<Tm>> {
        el.ls_prune(self.span)
    }

    fn arm(&mut self, el: &mut Elab<'a>, enter: bool) {
        if enter {
            crumb_push(el.ls_arm_crumb().unwrap_or_else(|| "in an arm".into()));
        } else {
            crumb_pop();
        }
    }

    fn eq_on_projections(&self) -> bool {
        true
    }

    fn eq_on_all(&self) -> bool {
        true
    }
}

/// One side of a split choice ([`Elab::split_choice`]): the goal at an
/// outcome `v` is `Eq(ty, f[v], other)` (or `Eq(ty, other, f[v])`), all at
/// depth `base` (`f` at `base + 1`).
struct ChoiceGoal {
    ty: Tm,
    f: Tm,
    other: Tm,
    left: bool,
    base: u32,
    fuel: u32,
    depth: u32,
    span: Span,
    failure: Option<Divergence>,
}

impl ChoiceGoal {
    fn sides(&self, el: &Elab<'_>, v: &Tm) -> (Tm, Tm, Tm) {
        let k = (el.depth() - self.base) as i64;
        let fv = super::tm::subst0(&sandblaster_kernel::util::shift_from(&self.f, k, 1), v);
        let o = shift(&self.other, k);
        let t = shift(&self.ty, k);
        if self.left { (t, fv, o) } else { (t, o, fv) }
    }
}

impl<'a> WalkGoal<'a> for ChoiceGoal {
    fn goal(&mut self, el: &mut Elab<'a>, v: &Tm) -> R<Tm> {
        let (t, l, r) = self.sides(el, v);
        Ok(mk::eq(t, l, r))
    }

    fn leaf(&mut self, el: &mut Elab<'a>, v: &Tm) -> R<Tm> {
        let (t, l, r) = self.sides(el, v);
        match el.meet(&t, &l, &r, self.span, self.fuel, self.depth + 1, true)? {
            Ok(p) => Ok(p),
            Err(d) => {
                self.failure = deeper(self.failure.take(), d);
                Err(abort(self.span))
            }
        }
    }

    fn prune(&mut self, el: &mut Elab<'a>) -> R<Option<Tm>> {
        el.ls_prune(self.span)
    }

    fn arm(&mut self, el: &mut Elab<'a>, enter: bool) {
        if enter {
            crumb_push(el.ls_arm_crumb().unwrap_or_else(|| "in an arm".into()));
        } else {
            crumb_pop();
        }
    }

    fn eq_on_projections(&self) -> bool {
        true
    }

    fn eq_on_all(&self) -> bool {
        true
    }
}

/// Whether `t` is a call of a function (a global applied to arguments).
fn code_call(t: &Tm) -> bool {
    let (h, args) = super::items::spine(t);
    matches!(&*h, Term::Global(_)) && !args.is_empty()
}

/// The code's value under its view: through the view's match on it
/// (`Option`), its projections (a slice's list) and its casts (`u64` to
/// `Nat`).
fn under_view(t: &Tm) -> Tm {
    let mut h = t.clone();
    loop {
        let next = match &*h {
            Term::Match { scrut, .. } => scrut.clone(),
            Term::Fst(x) | Term::Snd(x) => x.clone(),
            Term::Prim { args, .. } if args.len() == 1 => args[0].clone(),
            _ => return h,
        };
        h = next;
    }
}

/// Whether `t` mentions the variable of de Bruijn index `ix` (at its top).
fn mentions_var(t: &Tm, ix: u32) -> bool {
    let mut found = false;
    let _ = super::tm::map_post(t, 0, &mut |n, b| {
        if let Term::Var(sandblaster_kernel::term::Idx(i)) = &*n
            && *i == ix + b
        {
            found = true;
        }
        Some(n)
    });
    found
}

/// Whether `t` is a match (plain, or the dependent-match idiom applied to
/// its equation).
fn is_match(t: &Tm) -> bool {
    match &**t {
        Term::Match { .. } => true,
        Term::App { rel: Rel::Irr, fun, .. } => matches!(&**fun, Term::Match { .. }),
        _ => false,
    }
}

/// Whether a `let` value is a choice: a match, under `let`s.
fn is_choice(t: &Tm) -> bool {
    match &**t {
        Term::Let { body, .. } => is_choice(body),
        _ => is_match(t),
    }
}

/// `t` with the free variable of index `ix` abstracted: a body at depth
/// + 1 whose `Var(0)` stands for it (the other free variables shifted).
fn abstract_var(t: &Tm, ix: u32) -> Tm {
    super::tm::map_post(t, 0, &mut |n, b| match &*n {
        Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= b => Some(if *i - b == ix { mk::var(b) } else { mk::var(*i + 1) }),
        _ => Some(n),
    })
    .expect("abstract_var")
}
