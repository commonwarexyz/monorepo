//! Small helpers shared by the kernel modules (not part of any DESIGN.md rule
//! by themselves): budget accounting, evaluation-environment operations,
//! term constructors, and generic de Bruijn traversals (shifting, occurrence
//! checks, post-order rewriting).
//!
//! Budget accounting follows DESIGN.md §5.6: every evaluation or conversion
//! step consumes one unit and exhaustion is an error, never success.

use std::rc::Rc;

use crate::term::{Arm, BigInt, Idx, IndId, Lvl, Name, PrimOp, Rel, Term, Tm, Width};
use crate::value::{Arg, Budget, Closure, EnvEntry, EvalError, VEnv};

/// Consume one step of fuel. Running out of fuel — or of Rust stack, see
/// [`set_stack_limit`], or of heap, see below — is [`EvalError::OutOfFuel`],
/// never success.
///
/// The stack is inspected every [`STACK_CHECK_PERIOD`] steps (reading the
/// stack position and the thread-local limits on every step was a measurable
/// share of evaluation time); every recursive kernel function ticks, so at
/// most that many frames are added between two checks, far below the
/// margin between [`DEFAULT_STACK_LIMIT`] and a spawned thread's stack.
///
/// **Memory probe** (resource control, not part of the soundness argument):
/// at the same period, the process-wide soft allocation limit of
/// `sandblaster-memguard` is polled (two relaxed atomic loads); once the
/// process holds more heap than that limit, every kernel operation fails
/// with `OutOfFuel` instead of growing until the host runs out of memory.
/// Failing can only reject, never accept.
#[inline]
pub(crate) fn tick(b: &mut Budget) -> Result<(), EvalError> {
    if b.steps == 0 {
        return Err(EvalError::OutOfFuel);
    }
    b.steps -= 1;
    if b.steps.is_multiple_of(STACK_CHECK_PERIOD) && (stack_exceeded() || sandblaster_memguard::soft_limit_exceeded()) {
        return Err(EvalError::OutOfFuel);
    }
    Ok(())
}

/// See [`tick`].
const STACK_CHECK_PERIOD: u64 = 16;

// ---------------------------------------------------------------------------
// Stack guard: the kernel is recursive over terms and values, so deep
// non-tail recursion in evaluated programs could exhaust the Rust stack
// before the step budget. The outermost public entry point records the stack
// position; `tick` reports `OutOfFuel` once more than the (thread-local)
// limit is in use. No `unsafe`: only the address of a local is inspected.
// ---------------------------------------------------------------------------

/// Default stack allowance for kernel work on one thread (safe on the 2 MiB
/// stacks of spawned threads). Raise it with [`set_stack_limit`] when running
/// the kernel on a thread with a larger stack.
pub const DEFAULT_STACK_LIMIT: usize = 1536 << 10;

thread_local! {
    /// (stack position at the outermost kernel entry or 0, allowance).
    static STACK: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, DEFAULT_STACK_LIMIT)) };
}

/// Set the number of bytes of Rust stack kernel operations may use on the
/// current thread (beyond it they fail with `EvalError::OutOfFuel`). Keep it
/// comfortably below the thread's actual stack size.
pub fn set_stack_limit(bytes: usize) {
    STACK.with(|s| s.set((s.get().0, bytes)));
}

/// The current thread's kernel stack allowance.
pub fn stack_limit() -> usize {
    STACK.with(|s| s.get().1)
}

#[inline(never)]
fn stack_pos() -> usize {
    let marker = 0u8;
    std::hint::black_box(&marker) as *const u8 as usize
}

/// Is more than the allowed stack in use below the outermost kernel entry?
pub(crate) fn stack_exceeded() -> bool {
    let (base, limit) = STACK.with(|s| s.get());
    base != 0 && base.saturating_sub(stack_pos()) > limit
}

/// Records the stack position at the outermost kernel entry point.
pub(crate) struct StackGuard {
    outermost: bool,
}

impl StackGuard {
    pub(crate) fn enter() -> StackGuard {
        STACK.with(|s| {
            let (base, limit) = s.get();
            if base == 0 {
                s.set((stack_pos(), limit));
                StackGuard { outermost: true }
            } else {
                StackGuard { outermost: false }
            }
        })
    }
}

impl Drop for StackGuard {
    fn drop(&mut self) {
        if self.outermost {
            STACK.with(|s| s.set((0, s.get().1)));
        }
    }
}

/// Convert a level to an index at the given depth.
#[inline]
pub(crate) fn lvl_to_idx(depth: Lvl, l: Lvl) -> Idx {
    Idx(depth.0 - 1 - l.0)
}

/// Extend an evaluation environment with one entry (index 0 = the new entry).
pub(crate) fn venv_push(env: &VEnv, e: EnvEntry) -> VEnv {
    let mut v: Vec<EnvEntry> = Vec::with_capacity(env.0.len() + 1);
    v.extend(env.0.iter().cloned());
    v.push(e);
    VEnv(Rc::new(v))
}

/// Extend an evaluation environment with several entries (the last one ends
/// up at index 0).
pub(crate) fn venv_extend(env: &VEnv, es: impl IntoIterator<Item = EnvEntry>) -> VEnv {
    let mut v: Vec<EnvEntry> = env.0.as_ref().clone();
    v.extend(es);
    VEnv(Rc::new(v))
}

/// [`venv_push`] on an owned environment: extends it in place when it is
/// not shared (an evaluation-order-independent optimization: nothing else
/// can observe the vector).
pub(crate) fn venv_push_owned(mut env: VEnv, e: EnvEntry) -> VEnv {
    match Rc::get_mut(&mut env.0) {
        Some(v) => {
            v.push(e);
            env
        }
        None => venv_push(&env, e),
    }
}

/// [`venv_extend`] on an owned environment (in place when not shared).
pub(crate) fn venv_extend_owned(mut env: VEnv, es: impl IntoIterator<Item = EnvEntry>) -> VEnv {
    match Rc::get_mut(&mut env.0) {
        Some(v) => {
            v.extend(es);
            env
        }
        None => venv_extend(&env, es),
    }
}

/// Look up a de Bruijn index in an evaluation environment.
#[inline]
pub(crate) fn venv_get(env: &VEnv, i: Idx) -> Option<&EnvEntry> {
    let n = env.0.len();
    let i = i.0 as usize;
    if i < n { Some(&env.0[n - 1 - i]) } else { None }
}

/// Convert a spine argument into an environment entry.
#[inline]
pub(crate) fn arg_entry(a: &Arg) -> EnvEntry {
    match a {
        Arg::Rel(v) => EnvEntry::Rel(v.clone()),
        Arg::Irr(c) => EnvEntry::Irr(c.clone()),
    }
}

/// Convert an environment entry into a spine argument.
#[inline]
pub(crate) fn entry_arg(e: &EnvEntry) -> Arg {
    match e {
        EnvEntry::Rel(v) => Arg::Rel(v.clone()),
        EnvEntry::Irr(c) => Arg::Irr(c.clone()),
    }
}

/// A closure that denotes the irrelevant free variable at level `l`
/// (quoting it yields that variable; it is never forced).
pub(crate) fn irr_var_closure(l: Lvl) -> Closure {
    Closure {
        env: VEnv(Rc::new(vec![EnvEntry::Rel(Rc::new(crate::value::Value::Neu(crate::value::Neutral {
            head: crate::value::Head::Var(l),
            spine: Vec::new(),
        })))])),
        body: Rc::new(Term::Var(Idx(0))),
    }
}

// ---------------------------------------------------------------------------
// Term constructors (public: used by the front end, automation and tests).
// ---------------------------------------------------------------------------

/// Term constructors. Every function allocates a fresh [`Tm`].
pub mod mk {
    use super::*;

    pub fn name(s: &str) -> Name {
        Rc::from(s)
    }
    pub fn var(i: u32) -> Tm {
        Rc::new(Term::Var(Idx(i)))
    }
    pub fn global(g: crate::term::GlobalId) -> Tm {
        Rc::new(Term::Global(g))
    }
    pub fn ty() -> Tm {
        Rc::new(Term::Sort(crate::term::Sort::Type))
    }
    pub fn pi(n: &str, rel: Rel, dom: Tm, cod: Tm) -> Tm {
        Rc::new(Term::Pi { name: name(n), rel, dom, cod })
    }
    pub fn arrow(dom: Tm, cod_unshifted: Tm) -> Tm {
        Rc::new(Term::Pi { name: name("_"), rel: Rel::Rel, dom, cod: shift(&cod_unshifted, 1) })
    }
    pub fn lam(n: &str, rel: Rel, dom: Tm, body: Tm) -> Tm {
        Rc::new(Term::Lam { name: name(n), rel, dom, body })
    }
    pub fn app(f: Tm, a: Tm) -> Tm {
        Rc::new(Term::App { rel: Rel::Rel, fun: f, arg: a })
    }
    pub fn app_irr(f: Tm, a: Tm) -> Tm {
        Rc::new(Term::App { rel: Rel::Irr, fun: f, arg: a })
    }
    pub fn apps(f: Tm, args: impl IntoIterator<Item = (Rel, Tm)>) -> Tm {
        args.into_iter().fold(f, |f, (rel, arg)| Rc::new(Term::App { rel, fun: f, arg }))
    }
    pub fn let_(n: &str, rel: Rel, ty: Tm, val: Tm, body: Tm) -> Tm {
        Rc::new(Term::Let { name: name(n), rel, ty, val, body })
    }
    pub fn sigma(n: &str, snd_rel: Rel, fst: Tm, snd: Tm) -> Tm {
        Rc::new(Term::Sigma { name: name(n), snd_rel, fst, snd })
    }
    pub fn pair(ty: Tm, fst: Tm, snd: Tm) -> Tm {
        Rc::new(Term::Pair { ty, fst, snd })
    }
    pub fn fst(p: Tm) -> Tm {
        Rc::new(Term::Fst(p))
    }
    pub fn snd(p: Tm) -> Tm {
        Rc::new(Term::Snd(p))
    }
    pub fn eq(ty: Tm, lhs: Tm, rhs: Tm) -> Tm {
        Rc::new(Term::Eq { ty, lhs, rhs })
    }
    pub fn refl(ty: Tm, val: Tm) -> Tm {
        Rc::new(Term::Refl { ty, val })
    }
    pub fn ind(ind: IndId, params: Vec<Tm>) -> Tm {
        Rc::new(Term::Ind { ind, params })
    }
    pub fn ctor(ind: IndId, ctor: u32, params: Vec<Tm>, args: Vec<Tm>) -> Tm {
        Rc::new(Term::Ctor { ind, ctor, params, args })
    }
    pub fn int_ty(w: Width) -> Tm {
        Rc::new(Term::IntTy(w))
    }
    pub fn lit(w: Width, n: impl Into<BigInt>) -> Tm {
        Rc::new(Term::Lit { w, n: n.into() })
    }
    pub fn prim(op: PrimOp, args: Vec<Tm>, proofs: Vec<Tm>) -> Tm {
        Rc::new(Term::Prim { op, args, proofs })
    }
    pub fn bool_ty(b: IndId) -> Tm {
        ind(b, vec![])
    }
    pub fn bool_lit(b: IndId, v: bool) -> Tm {
        ctor(b, v as u32, vec![], vec![])
    }
    /// `Eq(Bool, t, true|false)`.
    pub fn eq_bool(b: IndId, t: Tm, v: bool) -> Tm {
        eq(bool_ty(b), t, bool_lit(b, v))
    }
    pub fn arm(names: &[&str], body: Tm) -> Arm {
        Arm { names: names.iter().map(|s| name(s)).collect(), body }
    }
}

// ---------------------------------------------------------------------------
// Generic traversals.
// ---------------------------------------------------------------------------

/// Number of variables bound by each child of a term, in the order the
/// children are visited by [`map_post`] / [`any_sub`].
pub(crate) fn children(t: &Term) -> Vec<(&Tm, u32)> {
    use Term::*;
    match t {
        Var(_) | Global(_) | Sort(_) | IntTy(_) | Lit { .. } | Erased => vec![],
        Pi { dom, cod, .. } => vec![(dom, 0), (cod, 1)],
        Lam { dom, body, .. } => vec![(dom, 0), (body, 1)],
        App { fun, arg, .. } => vec![(fun, 0), (arg, 0)],
        Let { ty, val, body, .. } => vec![(ty, 0), (val, 0), (body, 1)],
        Sigma { fst, snd, .. } => vec![(fst, 0), (snd, 1)],
        Pair { ty, fst, snd } => vec![(ty, 0), (fst, 0), (snd, 0)],
        Fst(p) | Snd(p) => vec![(p, 0)],
        Eq { ty, lhs, rhs } => vec![(ty, 0), (lhs, 0), (rhs, 0)],
        Refl { ty, val } => vec![(ty, 0), (val, 0)],
        Transport { ty, lhs, rhs, eq, motive, val } => {
            vec![(ty, 0), (lhs, 0), (rhs, 0), (eq, 0), (motive, 1), (val, 0)]
        }
        Ind { params, .. } => params.iter().map(|p| (p, 0)).collect(),
        Ctor { params, args, .. } => params.iter().chain(args.iter()).map(|p| (p, 0)).collect(),
        Match { params, scrut, motive, arms, .. } => {
            let mut v: Vec<(&Tm, u32)> = params.iter().map(|p| (p, 0)).collect();
            v.push((scrut, 0));
            v.push((motive, 1));
            for a in arms {
                v.push((&a.body, a.names.len() as u32));
            }
            v
        }
        Prim { args, proofs, .. } => args.iter().chain(proofs.iter()).map(|p| (p, 0)).collect(),
        Rec { args, proof } => {
            let mut v: Vec<(&Tm, u32)> = args.iter().map(|p| (p, 0)).collect();
            if let Some(p) = proof {
                v.push((p, 0));
            }
            v
        }
        Delta { args, .. } => args.iter().map(|p| (p, 0)).collect(),
        Unfold { args, val, .. } => {
            let mut v: Vec<(&Tm, u32)> = args.iter().map(|p| (p, 0)).collect();
            v.push((val, 0));
            v
        }
        Linarith { hyps, goal, .. } => {
            let mut v = Vec::new();
            for (p, s) in hyps {
                v.push((p, 0));
                v.push((s, 0));
            }
            v.push((goal, 0));
            v
        }
        BvRefl { ty, lhs, rhs } => vec![(ty, 0), (lhs, 0), (rhs, 0)],
        Absurd { ty, proof } => vec![(ty, 0), (proof, 0)],
        Axiom { args, .. } => args.iter().map(|p| (p, 0)).collect(),
    }
}

/// Rebuild a term from new children (same order as [`children`]).
pub(crate) fn rebuild_with(t: &Term, kids: Vec<Tm>) -> Tm {
    rebuild(t, kids.into_iter())
}

/// Rebuild a term from new children (same order as [`children`]).
fn rebuild(t: &Term, mut kids: std::vec::IntoIter<Tm>) -> Tm {
    use Term::*;
    let mut next = || kids.next().expect("rebuild: child count");
    let t2 = match t {
        Var(i) => Var(*i),
        Global(g) => Global(*g),
        Sort(s) => Sort(*s),
        IntTy(w) => IntTy(*w),
        Lit { w, n } => Lit { w: *w, n: n.clone() },
        Erased => Erased,
        Pi { name, rel, .. } => Pi { name: name.clone(), rel: *rel, dom: next(), cod: next() },
        Lam { name, rel, .. } => Lam { name: name.clone(), rel: *rel, dom: next(), body: next() },
        App { rel, .. } => App { rel: *rel, fun: next(), arg: next() },
        Let { name, rel, .. } => Let { name: name.clone(), rel: *rel, ty: next(), val: next(), body: next() },
        Sigma { name, snd_rel, .. } => Sigma { name: name.clone(), snd_rel: *snd_rel, fst: next(), snd: next() },
        Pair { .. } => Pair { ty: next(), fst: next(), snd: next() },
        Fst(_) => Fst(next()),
        Snd(_) => Snd(next()),
        Eq { .. } => Eq { ty: next(), lhs: next(), rhs: next() },
        Refl { .. } => Refl { ty: next(), val: next() },
        Transport { .. } => Transport { ty: next(), lhs: next(), rhs: next(), eq: next(), motive: next(), val: next() },
        Ind { ind, params } => Ind { ind: *ind, params: params.iter().map(|_| next()).collect() },
        Ctor { ind, ctor, params, args } => {
            Ctor { ind: *ind, ctor: *ctor, params: params.iter().map(|_| next()).collect(), args: args.iter().map(|_| next()).collect() }
        }
        Match { ind, params, arms, .. } => {
            let params = params.iter().map(|_| next()).collect();
            let scrut = next();
            let motive = next();
            let arms = arms.iter().map(|a| Arm { names: a.names.clone(), body: next() }).collect();
            Match { ind: *ind, params, scrut, motive, arms }
        }
        Prim { op, args, proofs } => {
            Prim { op: *op, args: args.iter().map(|_| next()).collect(), proofs: proofs.iter().map(|_| next()).collect() }
        }
        Rec { args, proof } => {
            let args = args.iter().map(|_| next()).collect();
            let proof = proof.as_ref().map(|_| next());
            Rec { args, proof }
        }
        Delta { def, args } => Delta { def: *def, args: args.iter().map(|_| next()).collect() },
        Unfold { def, args, to_body, .. } => {
            let args = args.iter().map(|_| next()).collect();
            Unfold { def: *def, args, to_body: *to_body, val: next() }
        }
        Linarith { hyps, cert, .. } => {
            let hyps = hyps.iter().map(|_| (next(), next())).collect();
            Linarith { hyps, goal: next(), cert: cert.clone() }
        }
        BvRefl { .. } => BvRefl { ty: next(), lhs: next(), rhs: next() },
        Absurd { .. } => Absurd { ty: next(), proof: next() },
        Axiom { ax, args } => Axiom { ax: *ax, args: args.iter().map(|_| next()).collect() },
    };
    Rc::new(t2)
}

fn tm_addr(t: &Tm) -> usize {
    Rc::as_ptr(t) as *const () as usize
}

/// Post-order rewrite: every node is rebuilt from its rewritten children and
/// then passed to `f` together with the number of binders crossed so far.
/// `f` must be a function of its arguments (it is called once per shared
/// node and binder depth: shared subterms — `Rc::strong_count > 1` — are
/// rewritten once per depth and stay shared, so a term DAG is not unfolded
/// into a tree).
pub(crate) fn map_post(t: &Tm, depth: u32, f: &mut dyn FnMut(Tm, u32) -> Tm) -> Tm {
    let mut memo: FxMap<(usize, u32), Tm> = FxMap::default();
    let mut keep: Vec<Tm> = Vec::new();
    map_post_memo(t, depth, f, &mut memo, &mut keep)
}

fn map_post_memo(t: &Tm, depth: u32, f: &mut dyn FnMut(Tm, u32) -> Tm, memo: &mut FxMap<(usize, u32), Tm>, keep: &mut Vec<Tm>) -> Tm {
    let shared = Rc::strong_count(t) > 1;
    if shared && let Some(r) = memo.get(&(tm_addr(t), depth)) {
        return r.clone();
    }
    let kids: Vec<Tm> = children(t).into_iter().map(|(c, k)| map_post_memo(c, depth + k, f, memo, keep)).collect();
    let node = if kids.is_empty() { t.clone() } else { rebuild(t, kids.into_iter()) };
    let r = f(node, depth);
    if shared {
        memo.insert((tm_addr(t), depth), r.clone());
        keep.push(t.clone());
    }
    r
}

/// Does any subterm (visited pre-order, with binder depth) satisfy `f`?
/// Shared subterms are visited once per binder depth (`f` must be a
/// function of its arguments; side effects of repeated calls are skipped).
pub(crate) fn any_sub(t: &Tm, depth: u32, f: &mut dyn FnMut(&Tm, u32) -> bool) -> bool {
    let mut seen: FxSet<(usize, u32)> = FxSet::default();
    any_sub_memo(t, depth, f, &mut seen)
}

fn any_sub_memo(t: &Tm, depth: u32, f: &mut dyn FnMut(&Tm, u32) -> bool, seen: &mut FxSet<(usize, u32)>) -> bool {
    // `t` is borrowed from its parent for the whole traversal, so its
    // address cannot be reused while `seen` lives.
    if Rc::strong_count(t) > 1 && !seen.insert((tm_addr(t), depth)) {
        return false;
    }
    if f(t, depth) {
        return true;
    }
    children(t).into_iter().any(|(c, k)| any_sub_memo(c, depth + k, f, seen))
}

/// Is `t` a proper DAG (some subterm reached through two parents)?
pub(crate) fn is_dag(t: &Tm) -> bool {
    let mut seen: FxSet<usize> = FxSet::default();
    let mut stack: Vec<&Tm> = vec![t];
    while let Some(n) = stack.pop() {
        if Rc::strong_count(n) > 1 && !seen.insert(tm_addr(n)) {
            return true;
        }
        stack.extend(children(n).into_iter().map(|(c, _)| c));
    }
    false
}

/// Does any node of `t` satisfy `f` (binder depth irrelevant)? Linear in
/// the term DAG.
pub(crate) fn any_node(t: &Tm, f: &mut dyn FnMut(&Tm) -> bool) -> bool {
    let mut seen: FxSet<usize> = FxSet::default();
    let mut stack: Vec<&Tm> = vec![t];
    while let Some(n) = stack.pop() {
        if Rc::strong_count(n) > 1 && !seen.insert(tm_addr(n)) {
            continue;
        }
        if f(n) {
            return true;
        }
        stack.extend(children(n).into_iter().map(|(c, _)| c));
    }
    false
}

/// Shift the free variables of `t` by `d` (which must not make an index
/// negative).
pub fn shift(t: &Tm, d: i64) -> Tm {
    shift_from(t, d, 0)
}

/// Shift the free variables `>= cutoff` of `t` by `d`.
pub fn shift_from(t: &Tm, d: i64, cutoff: u32) -> Tm {
    if d == 0 {
        return t.clone();
    }
    map_post(t, 0, &mut |n, depth| match &*n {
        Term::Var(Idx(i)) if *i >= depth + cutoff => Rc::new(Term::Var(Idx((*i as i64 + d) as u32))),
        _ => n,
    })
}

/// Does the variable with index `idx` (relative to `t`) occur free in `t`?
pub fn occurs(t: &Tm, idx: u32) -> bool {
    any_sub(t, 0, &mut |n, depth| matches!(&**n, Term::Var(Idx(i)) if *i == idx + depth))
}

// ---------------------------------------------------------------------------
// A fast, non-cryptographic hasher for the kernel's internal tables (memo
// keys are addresses, class ids and small integers; the inputs are the
// user's own programs, so hash flooding is not a concern). The algorithm is
// the Fx hash (rustc): `h = (h.rotl(5) ^ word) · K`.
// ---------------------------------------------------------------------------

/// The Fx hasher.
#[derive(Default, Clone, Copy)]
pub(crate) struct FxHasher {
    hash: u64,
}

const FX_K: u64 = 0x51_7c_c1_b7_27_22_0a_95;

impl FxHasher {
    #[inline]
    fn add(&mut self, w: u64) {
        self.hash = (self.hash.rotate_left(5) ^ w).wrapping_mul(FX_K);
    }
}

impl std::hash::Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let (chunks, rest) = bytes.as_chunks::<8>();
        for c in chunks {
            self.add(u64::from_le_bytes(*c));
        }
        if !rest.is_empty() {
            let mut buf = [0u8; 8];
            buf[..rest.len()].copy_from_slice(rest);
            self.add(u64::from_le_bytes(buf));
        }
    }
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i);
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }
    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

/// A `HashMap` with [`FxHasher`].
pub(crate) type FxMap<K, V> = std::collections::HashMap<K, V, std::hash::BuildHasherDefault<FxHasher>>;
/// A `HashSet` with [`FxHasher`].
pub(crate) type FxSet<K> = std::collections::HashSet<K, std::hash::BuildHasherDefault<FxHasher>>;
