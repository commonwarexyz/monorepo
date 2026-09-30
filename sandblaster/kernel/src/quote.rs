//! Read-back of values into terms (DESIGN.md §5.9, §5.11, §8.2).
//!
//! * Closures under binders (Π/Σ codomains, λ bodies, match arms and
//!   motives, transport motives) are quoted by instantiating them with fresh
//!   variables and evaluating (NbE), on an internal budget; if that budget
//!   runs out the closure is quoted by substitution instead (always
//!   terminates, the result is merely not normalized).
//! * Irrelevant closures (proofs) are **never** evaluated: they are quoted by
//!   substitution (their free variables are replaced by the quoted
//!   environment values).
//! * Typed quoting ([`Quoter::typed`]) propagates the expected type into the
//!   value so that pairs get their Σ type (`Term::Pair` needs it; a value
//!   pair does not carry it). Untyped quoting emits `Erased` for the type of a
//!   pair whose Σ type is unknown, and for the (unstored) proofs of `absurd`
//!   and `transport` neutrals; such terms must be completed by the caller
//!   before they can be checked.
//! * Sharing (`share = true`): every non-trivial node of the top-level value
//!   DAG (not entering closures) with more than one parent and an inferable
//!   type is bound once with a relevant `Let` at the root, in dependency
//!   order. Because evaluation is call-by-value, every such node was computed
//!   unconditionally at that level, so hoisting the binding to the root
//!   changes nothing. Leaves (literals, variables, sorts, nullary
//!   constructors) are never let-bound.
//! * Abstraction ([`Quoter::abstracting`]): every subvalue convertible with a
//!   target is replaced by a fresh variable (used by `abstract_occurrences`),
//!   including neutral heads and spine prefixes — a stuck scrutinee `c` of
//!   `match c { .. }`, a partial application — and, on request, data
//!   subterms of irrelevant closures (proof terms), evaluated in the
//!   closure's environment.
//! * Memo (when neither sharing, abstraction nor a node limit is active):
//!   neutral and constructor nodes are memoized by (address, depth), and
//!   closures quoted by substitution (proofs) by (environment address, body
//!   address, depth, binders). The quoted term shares `Rc` subterms, so
//!   reading back a value DAG — a symbolic hash, or proofs that refer to an
//!   earlier proof several times — takes time and memory linear in the DAG.
//!   A hit returns exactly the term the quoter would recompute there: the
//!   key fixes the node and the quoting depth (levels become indices
//!   relative to it), and the only other input, the context types of typed
//!   quoting, is covered by dropping every entry deeper than a level whose
//!   type changes after it was read. For that, the type read for a level is
//!   a function of the path to the read: the context's (restored when a
//!   call from outside starts) or the one its binder set (the binders of a
//!   closure quoted by substitution set `None`) (AUDIT.md §7.5).
//! * [`Quoter::bounded`] elides everything past a node budget (diagnostics).

use std::collections::HashMap;
use std::rc::Rc;

use crate::api::Env;
use crate::conv::Conv;
use crate::eval::{Ev, clone_elim, clone_head, neu, var_v};
use crate::prim::{self, PrimTy};
use crate::term::{Arm, Idx, Lvl, Rel, Sort, Term, Tm};
use crate::util::{irr_var_closure, lvl_to_idx, map_post, venv_get};
use crate::value::{Arg, Budget, Closure, Elim, EnvEntry, Head, Neutral, V, Value};

fn addr(v: &V) -> usize {
    Rc::as_ptr(v) as *const () as usize
}

/// Internal budget for evaluating closures while quoting.
const QUOTE_BUDGET: u64 = 50_000_000;

/// A read-back memo key (the depth is the map's index): a value, or a
/// closure quoted by substitution — the addresses of its environment vector
/// and body, and the number of binders of its own.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    Val(usize),
    Clo(usize, usize, u32),
}

struct Share {
    /// Address → position of the node's let binder.
    pos: HashMap<usize, usize>,
    /// Level of the first let binder.
    base: u32,
    /// Only binders with position `< limit` are in scope.
    limit: usize,
    _keep: Vec<V>,
}

struct Target {
    value: V,
    /// Level of the abstracted variable.
    lvl: Lvl,
    memo: HashMap<usize, bool>,
    keep: Vec<V>,
    /// Also abstract occurrences inside irrelevant closures (proof terms).
    in_proofs: bool,
    /// Spine length of the target if it is a neutral (only prefixes of that
    /// length can be convertible with it).
    spine_len: Option<usize>,
    /// Proof subterms still to test (a bound on the work spent in proofs).
    proof_fuel: u64,
}

/// Budget of one conversion test against the abstraction target.
const TARGET_CONV_BUDGET: u64 = 1_000_000;
/// Budget of evaluating one proof subterm for the abstraction test.
const PROOF_EVAL_BUDGET: u64 = 100_000;
/// Number of proof subterms tested per abstraction.
const PROOF_NODES: u64 = 50_000;

/// Quoting state.
pub(crate) struct Quoter<'e> {
    env: &'e Env,
    /// Types of context variables by level (typed quoting); `None` entries
    /// are unknown.
    types: Vec<Option<V>>,
    typed: bool,
    share: Option<Share>,
    target: Option<Target>,
    budget: Budget,
    /// Set if the abstraction's conversion checks ran out of budget.
    pub failed: bool,
    /// Diagnostics only: the number of nodes still to quote; beyond it every
    /// subterm is elided (quoted as `Erased`, printed `_`).
    limit: Option<u64>,
    /// Read-back memo, one map per quoting depth (module docs). Not used
    /// while sharing, abstracting or bounded (those depend on more than the
    /// node). `memo[d]` holds terms quoted at depth `d`, which read the types
    /// of levels `< d` only (and of their own binders, which they set).
    memo: Vec<crate::util::FxMap<Key, Tm>>,
    /// Levels whose type was read (a variable head applied to a spine) since
    /// `memo` was last cut there: changing it drops `memo[l + 1..]`.
    read: Vec<bool>,
    /// The keyed values and closures, kept alive (no address reuse).
    memo_keep: Vec<V>,
    clo_keep: Vec<Closure>,
    /// Off only in the memo's reference tests (unmemoized quoting).
    memo_on: bool,
    /// The context types given to [`Quoter::typed`] (`types` is changed by
    /// binders), and the nesting of calls (0: a call from outside).
    ctx: Vec<Option<V>>,
    nest: u32,
    /// Evaluation memo for closure instantiations (shared closure bodies
    /// are evaluated as DAGs; see `eval::EvalMemo`).
    ev_memo: Rc<std::cell::RefCell<crate::eval::EvalMemo>>,
}

impl<'e> Quoter<'e> {
    pub fn untyped(env: &'e Env) -> Self {
        Quoter {
            env,
            types: Vec::new(),
            typed: false,
            share: None,
            target: None,
            budget: Budget { steps: QUOTE_BUDGET },
            failed: false,
            limit: None,
            memo: Vec::new(),
            read: Vec::new(),
            memo_keep: Vec::new(),
            clo_keep: Vec::new(),
            memo_on: true,
            ctx: Vec::new(),
            nest: 0,
            ev_memo: Default::default(),
        }
    }

    /// Typed quoting with the types of the context variables (by level).
    pub fn typed(env: &'e Env, types: Vec<Option<V>>) -> Self {
        Quoter { ctx: types.clone(), types, typed: true, ..Quoter::untyped(env) }
    }

    /// Size-bounded typed quoting for diagnostics: after `nodes` nodes the
    /// rest is elided (`_`), so rendering a large value DAG stays cheap.
    pub fn bounded(env: &'e Env, types: Vec<Option<V>>, nodes: u64) -> Self {
        Quoter { limit: Some(nodes), ..Quoter::typed(env, types) }
    }

    /// Replace subvalues convertible with `t` by the variable at level `lvl`:
    /// every value visited in relevant positions, every prefix of a neutral
    /// (head, stuck scrutinee, partial application), and — with `in_proofs`
    /// — every data subterm of an irrelevant closure (proof), evaluated in
    /// the closure's environment.
    pub fn abstracting(mut self, t: V, lvl: Lvl, in_proofs: bool) -> Self {
        let spine_len = match &*t {
            Value::Neu(n) => Some(n.spine.len()),
            _ => None,
        };
        self.target = Some(Target { value: t, lvl, memo: HashMap::new(), keep: Vec::new(), in_proofs, spine_len, proof_fuel: PROOF_NODES });
        self
    }

    fn ev(&self) -> Ev<'e> {
        Ev::new(self.env).sharing(self.ev_memo.clone())
    }

    fn set_type(&mut self, l: Lvl, ty: Option<V>) {
        let i = l.0 as usize;
        if self.types.len() <= i {
            self.types.resize(i + 1, None);
        }
        // Terms memoized deeper than `l` may have used the old type.
        let same = match (&self.types[i], &ty) {
            (Some(a), Some(b)) => Rc::ptr_eq(a, b),
            (a, b) => a.is_none() && b.is_none(),
        };
        if !same && self.read.get(i) == Some(&true) {
            self.memo.truncate(i + 1);
            self.read.truncate(i);
        }
        self.types[i] = ty;
    }

    /// The type of level `l` for a variable head applied to a spine (typed
    /// quoting), recording the read for the memo.
    fn type_of(&mut self, l: Lvl) -> Option<V> {
        let i = l.0 as usize;
        if self.read.len() <= i {
            self.read.resize(i + 1, false);
        }
        self.read[i] = true;
        self.types.get(i).cloned().flatten()
    }

    /// Enter a call; one from outside at `depth` starts from the context's
    /// types below `depth` (an earlier call may have bound those levels).
    fn enter(&mut self, depth: Lvl) {
        if self.nest == 0 && self.typed {
            for l in 0..self.types.len().min(depth.0 as usize) {
                self.set_type(Lvl(l as u32), self.ctx.get(l).cloned().flatten());
            }
        }
        self.nest += 1;
    }

    fn memo_active(&self) -> bool {
        self.memo_on && self.share.is_none() && self.target.is_none() && self.limit.is_none()
    }

    fn memo_get(&self, depth: Lvl, k: Key) -> Option<Tm> {
        self.memo.get(depth.0 as usize)?.get(&k).cloned()
    }

    fn memo_put(&mut self, depth: Lvl, k: Key, t: &Tm) {
        let d = depth.0 as usize;
        if self.memo.len() <= d {
            self.memo.resize_with(d + 1, Default::default);
        }
        self.memo[d].insert(k, t.clone());
    }

    /// Quote `v` at `depth` (with sharing if requested).
    pub fn quote_root(&mut self, depth: Lvl, v: &V, ty: Option<&V>, share: bool) -> Tm {
        if !share {
            return self.q(depth, v, ty);
        }
        self.enter(depth);
        let (order, _parents) = shared_nodes(v);
        // Keep only nodes with an inferable type.
        let mut cands: Vec<(V, V)> = Vec::new();
        for n in order {
            if let Some(t) = self.vtype(depth, &n) {
                cands.push((n, t));
            }
        }
        let mut pos = HashMap::new();
        for (k, (n, _)) in cands.iter().enumerate() {
            pos.insert(addr(n), k);
        }
        self.share = Some(Share { pos, base: depth.0, limit: 0, _keep: cands.iter().map(|c| c.0.clone()).collect() });
        let mut lets: Vec<(Tm, Tm)> = Vec::with_capacity(cands.len());
        for (k, (n, t)) in cands.iter().enumerate() {
            self.share.as_mut().unwrap().limit = k;
            let d = Lvl(depth.0 + k as u32);
            let ty_t = self.q(d, t, None);
            let val_t = self.q_node(d, n, Some(t));
            lets.push((ty_t, val_t));
        }
        let l = cands.len();
        self.share.as_mut().unwrap().limit = l;
        let mut body = self.q(Lvl(depth.0 + l as u32), v, ty);
        for (k, (ty_t, val_t)) in lets.into_iter().enumerate().rev() {
            body = Rc::new(Term::Let { name: Rc::from(format!("s{k}")), rel: Rel::Rel, ty: ty_t, val: val_t, body });
        }
        self.share = None;
        self.nest -= 1;
        body
    }

    /// Quote a value.
    pub fn q(&mut self, depth: Lvl, v: &V, ty: Option<&V>) -> Tm {
        self.enter(depth);
        let t = self.q_val(depth, v, ty);
        self.nest -= 1;
        t
    }

    fn q_val(&mut self, depth: Lvl, v: &V, ty: Option<&V>) -> Tm {
        if let Some(l) = &mut self.limit {
            if *l == 0 {
                return Rc::new(Term::Erased);
            }
            *l -= 1;
        }
        if let Some(t) = self.target_hit(depth, v) {
            return t;
        }
        if let Some(s) = &self.share
            && let Some(&k) = s.pos.get(&addr(v))
            && k < s.limit
        {
            return Rc::new(Term::Var(lvl_to_idx(depth, Lvl(s.base + k as u32))));
        }
        // Nodes whose read-back does not depend on the expected type:
        // neutrals and constructors (pairs and λs do).
        let memo = self.memo_active() && (matches!(&**v, Value::Neu(_)) || matches!(&**v, Value::Ctor { args, .. } if !args.is_empty()));
        if memo && let Some(t) = self.memo_get(depth, Key::Val(addr(v))) {
            return t;
        }
        let t = self.q_node(depth, v, ty);
        if memo {
            self.memo_put(depth, Key::Val(addr(v)), &t);
            self.memo_keep.push(v.clone());
        }
        t
    }

    /// Is `v` (at `depth`) convertible with the abstraction target? A
    /// conversion that runs out of budget counts as a miss and marks the
    /// abstraction as failed.
    fn is_target(&mut self, depth: Lvl, v: &V) -> bool {
        let Some(tgt) = self.target.as_ref() else { return false };
        let mut b = Budget { steps: TARGET_CONV_BUDGET };
        match Conv::new(self.env).conv(depth, v, &tgt.value, &mut b) {
            Ok(h) => h,
            Err(_) => {
                self.failed = true;
                false
            }
        }
    }

    /// The longest proper prefix of the neutral `n` (its head and first `k`
    /// eliminators) convertible with the target: `(k, variable, type of the
    /// prefix)`. This abstracts a stuck scrutinee (`match c { .. }` with
    /// target `c`), a neutral head, or a partial application, which are not
    /// values of their own. Only prefixes whose spine length equals the
    /// target's can be convertible (neutrals of different spine lengths never
    /// are), so at most one conversion test is made per neutral.
    fn prefix_hit(&mut self, depth: Lvl, n: &Neutral) -> Option<(usize, Tm, Option<V>)> {
        let tgt = self.target.as_ref()?;
        let k = tgt.spine_len?;
        let lvl = tgt.lvl;
        if k >= n.spine.len() {
            return None;
        }
        let prefix = prefix_value(n, k);
        if !self.is_target(depth, &prefix) {
            return None;
        }
        let ty = if self.typed { self.vtype(depth, &prefix) } else { None };
        Some((k, Rc::new(Term::Var(lvl_to_idx(depth, lvl))), ty))
    }

    fn target_hit(&mut self, depth: Lvl, v: &V) -> Option<Tm> {
        let tgt = self.target.as_mut()?;
        let a = addr(v);
        let hit = match tgt.memo.get(&a) {
            Some(h) => *h,
            None => {
                let mut b = Budget { steps: TARGET_CONV_BUDGET };
                let r = Conv::new(self.env).conv(depth, v, &tgt.value, &mut b);
                let h = match r {
                    Ok(h) => h,
                    Err(_) => {
                        self.failed = true;
                        false
                    }
                };
                tgt.memo.insert(a, h);
                tgt.keep.push(v.clone());
                h
            }
        };
        if hit { Some(Rc::new(Term::Var(lvl_to_idx(depth, tgt.lvl)))) } else { None }
    }

    /// Instantiate a closure with fresh variables and quote the result
    /// (substitution fallback when the internal budget is exhausted).
    fn q_under(&mut self, depth: Lvl, c: &Closure, es: Vec<EnvEntry>, ty: Option<&V>) -> Tm {
        let n = es.len() as u32;
        let d2 = Lvl(depth.0 + n);
        let mut ev = self.ev();
        match ev.inst_n_root(c, es, d2, &mut self.budget) {
            Ok(v) => self.q(d2, &v, ty),
            Err(_) => self.q_clo(depth, c, n),
        }
    }

    /// Quote a closure by substitution; `binders` extra variables (levels
    /// `depth..depth+binders`) are bound by the closure body itself.
    pub fn q_clo(&mut self, depth: Lvl, c: &Closure, binders: u32) -> Tm {
        self.enter(depth);
        let t = self.q_clo_in(depth, c, binders);
        self.nest -= 1;
        t
    }

    fn q_clo_in(&mut self, depth: Lvl, c: &Closure, binders: u32) -> Tm {
        if self.target.as_ref().is_some_and(|t| t.in_proofs) {
            let mut locals = Vec::new();
            for k in 0..binders {
                locals.push(EnvEntry::Rel(var_v(Lvl(depth.0 + k))));
            }
            return self.abs_clo(depth, &c.env, &c.body, binders, &mut locals);
        }
        // A closure is its environment and body (both immutable): the result
        // is a function of them, `depth` and `binders`.
        let key = Key::Clo(Rc::as_ptr(&c.env.0) as *const () as usize, Rc::as_ptr(&c.body) as *const () as usize, binders);
        let memo = self.memo_active();
        if memo && let Some(t) = self.memo_get(depth, key) {
            return t;
        }
        let env = c.env.clone();
        // The body's binders (its own and those in it) have no known type:
        // `None` (held by levels `depth..depth + unset`; a call at `d` sets
        // levels `≥ d` only; untyped, `types` holds only `None`).
        let mut unset = 0;
        let t = map_post(&c.body, binders, &mut |node, local| match &*node {
            Term::Var(Idx(i)) if *i >= local => {
                let d = Lvl(depth.0 + local);
                for l in unset..local {
                    self.set_type(Lvl(depth.0 + l), None);
                }
                unset = local;
                match venv_get(&env, Idx(i - local)) {
                    Some(EnvEntry::Rel(v)) => self.q(d, v, None),
                    Some(EnvEntry::Irr(c2)) => self.q_clo(d, c2, 0),
                    None => node,
                }
            }
            _ => node,
        });
        if memo {
            self.memo_put(depth, key, &t);
            self.clo_keep.push(c.clone());
        }
        t
    }

    /// Abstraction inside a closure body (proof terms): top-down, a data
    /// subterm whose value (in the closure's environment, local binders as
    /// fresh variables) is convertible with the target becomes the
    /// abstraction variable; free variables are quoted from the environment
    /// (with the target test). `local` binders of the body are in scope;
    /// `locals` holds their fresh values.
    fn abs_clo(&mut self, depth: Lvl, env: &crate::value::VEnv, t: &Tm, local: u32, locals: &mut Vec<EnvEntry>) -> Tm {
        let d = Lvl(depth.0 + local);
        if let Term::Var(Idx(i)) = &**t {
            if *i < local {
                return t.clone();
            }
            return match venv_get(env, Idx(i - local)) {
                Some(EnvEntry::Rel(v)) => {
                    let v = v.clone();
                    self.q(d, &v, None)
                }
                Some(EnvEntry::Irr(c2)) => {
                    let c2 = c2.clone();
                    self.q_clo(d, &c2, 0)
                }
                None => t.clone(),
            };
        }
        let testable = matches!(
            &**t,
            Term::App { .. }
                | Term::Prim { .. }
                | Term::Fst(_)
                | Term::Snd(_)
                | Term::Match { .. }
                | Term::Global(_)
                | Term::Ctor { .. }
                | Term::Pair { .. }
        );
        if testable
            && let Some(tgt) = self.target.as_mut()
            && tgt.proof_fuel > 0
        {
            tgt.proof_fuel -= 1;
            let lvl = tgt.lvl;
            let venv = crate::util::venv_extend(env, locals.iter().cloned());
            let mut b = Budget { steps: PROOF_EVAL_BUDGET };
            if let Ok(v) = Ev::new(self.env).eval(&venv, d, t, &mut b)
                && self.is_target(d, &v)
            {
                return Rc::new(Term::Var(lvl_to_idx(d, lvl)));
            }
        }
        let kids: Vec<(Tm, u32)> = crate::util::children(t).into_iter().map(|(c, k)| (c.clone(), k)).collect();
        if kids.is_empty() {
            return t.clone();
        }
        let mut out = Vec::with_capacity(kids.len());
        for (c, k) in kids {
            for j in 0..k {
                locals.push(EnvEntry::Rel(var_v(Lvl(d.0 + j))));
            }
            out.push(self.abs_clo(depth, env, &c, local + k, locals));
            locals.truncate(locals.len() - k as usize);
        }
        crate::util::rebuild_with(t, out)
    }

    fn q_arg(&mut self, depth: Lvl, a: &Arg, ty: Option<&V>) -> (Rel, Tm) {
        match a {
            Arg::Rel(v) => (Rel::Rel, self.q(depth, v, ty)),
            Arg::Irr(c) => (Rel::Irr, self.q_clo(depth, c, 0)),
        }
    }

    fn fresh(&mut self, depth: Lvl, rel: Rel, ty: &V) -> EnvEntry {
        let e = self.ev().fresh(depth, rel, ty);
        if self.typed {
            self.set_type(depth, Some(ty.clone()));
        }
        e
    }

    fn q_node(&mut self, depth: Lvl, v: &V, ty: Option<&V>) -> Tm {
        let typed = self.typed;
        let t = match &**v {
            Value::Sort(s) => Term::Sort(*s),
            Value::IntTy(w) => Term::IntTy(*w),
            Value::Lit { w, n } => Term::Lit { w: *w, n: n.clone() },
            Value::Pi { name, rel, dom, cod } => {
                let dom_t = self.q(depth, dom, None);
                let x = self.fresh(depth, *rel, dom);
                let cod_t = self.q_under(depth, cod, vec![x], None);
                Term::Pi { name: name.clone(), rel: *rel, dom: dom_t, cod: cod_t }
            }
            Value::Lam { name, rel, dom, body } => {
                let dom_t = self.q(depth, dom, None);
                let x = self.fresh(depth, *rel, dom);
                let body_ty = match ty.map(|t| &**t) {
                    Some(Value::Pi { cod, .. }) if typed => self.inst_ty(cod, vec![x.clone()], Lvl(depth.0 + 1)),
                    _ => None,
                };
                let body_t = self.q_under(depth, body, vec![x], body_ty.as_ref());
                Term::Lam { name: name.clone(), rel: *rel, dom: dom_t, body: body_t }
            }
            Value::Sigma { name, snd_rel, fst, snd } => {
                let fst_t = self.q(depth, fst, None);
                let x = self.fresh(depth, Rel::Rel, fst);
                let snd_t = self.q_under(depth, snd, vec![x], None);
                Term::Sigma { name: name.clone(), snd_rel: *snd_rel, fst: fst_t, snd: snd_t }
            }
            // The eta-expansion of an array variable reads back as the variable.
            Value::Pair { .. } if eta_var(self.env, v).is_some() => Term::Var(lvl_to_idx(depth, eta_var(self.env, v).unwrap())),
            Value::Pair { fst, snd } => match ty.map(|t| &**t) {
                Some(Value::Sigma { fst: a, snd: bcl, .. }) => {
                    let ty_t = self.q(depth, ty.unwrap(), None);
                    let fst_t = self.q(depth, fst, Some(a));
                    let b = self.inst_ty(bcl, vec![EnvEntry::Rel(fst.clone())], depth);
                    let (_, snd_t) = self.q_arg(depth, snd, b.as_ref());
                    Term::Pair { ty: ty_t, fst: fst_t, snd: snd_t }
                }
                _ => {
                    let fst_t = self.q(depth, fst, None);
                    let (_, snd_t) = self.q_arg(depth, snd, None);
                    Term::Pair { ty: Rc::new(Term::Erased), fst: fst_t, snd: snd_t }
                }
            },
            Value::Eq { ty: t, lhs, rhs } => {
                Term::Eq { ty: self.q(depth, t, None), lhs: self.q(depth, lhs, Some(t)), rhs: self.q(depth, rhs, Some(t)) }
            }
            Value::Refl { ty: t, val } => Term::Refl { ty: self.q(depth, t, None), val: self.q(depth, val, Some(t)) },
            Value::Ind { ind, params } => Term::Ind { ind: *ind, params: params.iter().map(|p| self.q(depth, p, None)).collect() },
            Value::Ctor { ind, ctor, params, args } => {
                let params_t = params.iter().map(|p| self.q(depth, p, None)).collect();
                let ftys = if typed { self.field_types(depth, *ind, *ctor, params, args) } else { vec![] };
                let args_t = args.iter().enumerate().map(|(i, a)| self.q_arg(depth, a, ftys.get(i).and_then(|t| t.as_ref())).1).collect();
                Term::Ctor { ind: *ind, ctor: *ctor, params: params_t, args: args_t }
            }
            Value::Neu(n) => return self.q_neutral(depth, n),
        };
        Rc::new(t)
    }

    /// Instantiate a type closure (typed quoting only; failures give `None`).
    fn inst_ty(&mut self, c: &Closure, es: Vec<EnvEntry>, depth: Lvl) -> Option<V> {
        let mut ev = self.ev();
        ev.inst_n(c, es, depth, &mut self.budget).ok()
    }

    /// Types of the fields of constructor `ctor` applied to `params`/`args`.
    fn field_types(&mut self, depth: Lvl, ind: crate::term::IndId, ctor: u32, params: &[V], args: &[Arg]) -> Vec<Option<V>> {
        let env = self.env;
        let Some(c) = env.inds.get(ind.0 as usize).and_then(|i| i.ctors.get(ctor as usize)) else { return vec![] };
        let mut venv: Vec<EnvEntry> = params.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
        let mut out = Vec::with_capacity(c.fields.len());
        for (i, (_, _, fty)) in c.fields.iter().enumerate() {
            let mut ev = self.ev();
            let t = ev.eval(&crate::value::VEnv(Rc::new(venv.clone())), depth, fty, &mut self.budget).ok();
            out.push(t);
            match args.get(i) {
                Some(a) => venv.push(crate::util::arg_entry(a)),
                None => break,
            }
        }
        out
    }

    fn q_neutral(&mut self, depth: Lvl, n: &Neutral) -> Tm {
        let (mut t, mut ty, start) = match self.prefix_hit(depth, n) {
            Some(hit) => hit_parts(hit),
            None => {
                let (t, ty) = self.q_head(depth, &n.head, !n.spine.is_empty());
                (t, ty, 0)
            }
        };
        for (i, e) in n.spine.iter().enumerate().skip(start) {
            match e {
                Elim::App(a) => {
                    let (dom, cod) = match ty.as_deref() {
                        Some(Value::Pi { dom, cod, .. }) => (Some(dom.clone()), Some(cod.clone())),
                        _ => (None, None),
                    };
                    let (rel, at) = self.q_arg(depth, a, dom.as_ref());
                    t = Rc::new(Term::App { rel, fun: t, arg: at });
                    ty = cod.and_then(|c| self.inst_ty(&c, vec![crate::util::arg_entry(a)], depth));
                }
                Elim::Fst => {
                    ty = match ty.as_deref() {
                        Some(Value::Sigma { fst, .. }) => Some(fst.clone()),
                        _ => None,
                    };
                    t = Rc::new(Term::Fst(t));
                }
                Elim::Snd => {
                    ty = match ty.as_deref() {
                        Some(Value::Sigma { snd, .. }) => {
                            let prefix = prefix_value(n, i);
                            let f = self.ev().fst(&prefix);
                            self.inst_ty(snd, vec![EnvEntry::Rel(f)], depth)
                        }
                        _ => None,
                    };
                    t = Rc::new(Term::Snd(t));
                }
                Elim::Match { ind, params, motive, arms } => {
                    let params_t: Vec<Tm> = params.iter().map(|p| self.q(depth, p, None)).collect();
                    let ind_v = Rc::new(Value::Ind { ind: *ind, params: params.clone() });
                    let y = self.fresh(depth, Rel::Rel, &ind_v);
                    let motive_t = self.q_under(depth, motive, vec![y], None);
                    let env = self.env;
                    let ctors = env.inds.get(ind.0 as usize).map(|i| i.ctors.clone()).unwrap_or_default();
                    let mut arms_t = Vec::with_capacity(arms.len());
                    for (k, arm) in arms.iter().enumerate() {
                        let fields = ctors.get(k).map(|c| c.fields.clone()).unwrap_or_default();
                        let mut es = Vec::with_capacity(fields.len());
                        let mut fenv: Vec<EnvEntry> = params.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
                        for (j, (_, rel, fty)) in fields.iter().enumerate() {
                            let l = Lvl(depth.0 + j as u32);
                            let ftv = {
                                let mut ev = self.ev();
                                ev.eval(&crate::value::VEnv(Rc::new(fenv.clone())), l, fty, &mut self.budget).ok()
                            };
                            // Every binder sets the type of its level (the memo's invariant).
                            let e = match &ftv {
                                Some(ft) => self.fresh(l, *rel, ft),
                                None => {
                                    if self.typed {
                                        self.set_type(l, None);
                                    }
                                    if *rel == Rel::Irr { EnvEntry::Irr(irr_var_closure(l)) } else { EnvEntry::Rel(var_v(l)) }
                                }
                            };
                            fenv.push(e.clone());
                            es.push(e);
                        }
                        let d2 = Lvl(depth.0 + es.len() as u32);
                        let arm_ty = if self.typed {
                            let cv = Rc::new(Value::Ctor {
                                ind: *ind,
                                ctor: k as u32,
                                params: params.clone(),
                                args: es.iter().map(crate::util::entry_arg).collect(),
                            });
                            self.inst_ty(motive, vec![EnvEntry::Rel(cv)], d2)
                        } else {
                            None
                        };
                        let names = fields.iter().map(|f| f.0.clone()).collect();
                        let body = self.q_under(depth, arm, es, arm_ty.as_ref());
                        arms_t.push(Arm { names, body });
                    }
                    ty = if self.typed {
                        let prefix = prefix_value(n, i);
                        self.inst_ty(motive, vec![EnvEntry::Rel(prefix)], depth)
                    } else {
                        None
                    };
                    t = Rc::new(Term::Match { ind: *ind, params: params_t, scrut: t, motive: motive_t, arms: arms_t });
                }
            }
        }
        t
    }

    /// The head's term and type (`spine`: the type is used; a variable's
    /// type is read only then).
    fn q_head(&mut self, depth: Lvl, h: &Head, spine: bool) -> (Tm, Option<V>) {
        let typed = self.typed;
        match h {
            Head::Var(l) => {
                let ty = if typed && spine { self.type_of(*l) } else { None };
                (Rc::new(Term::Var(lvl_to_idx(depth, *l))), ty)
            }
            Head::Global { def, args } => {
                let env = self.env;
                let mut ty = env.defs.get(def.0 as usize).map(|d| d.ty_val.clone());
                let mut t: Tm = Rc::new(Term::Global(*def));
                for a in args {
                    let (dom, cod) = match ty.as_deref() {
                        Some(Value::Pi { dom, cod, .. }) => (Some(dom.clone()), Some(cod.clone())),
                        _ => (None, None),
                    };
                    let (rel, at) = self.q_arg(depth, a, dom.as_ref());
                    t = Rc::new(Term::App { rel, fun: t, arg: at });
                    ty = cod.and_then(|c| self.inst_ty(&c, vec![crate::util::arg_entry(a)], depth));
                }
                (t, ty)
            }
            Head::Prim { op, args, proofs } => {
                let sig = prim::prim_sig(*op);
                let args_t = args
                    .iter()
                    .enumerate()
                    .map(|(i, a)| {
                        let w = sig.as_ref().and_then(|s| s.args.get(i).copied());
                        let ty = w.map(|w| Rc::new(Value::IntTy(w)));
                        self.q(depth, a, ty.as_ref())
                    })
                    .collect();
                let proofs_t = proofs.iter().map(|c| self.q_clo(depth, c, 0)).collect();
                let ty = sig.map(|s| match s.result {
                    PrimTy::Int(w) => Rc::new(Value::IntTy(w)),
                    PrimTy::Bool => Rc::new(Value::Ind { ind: self.env.bool_id, params: vec![] }),
                });
                (Rc::new(Term::Prim { op: *op, args: args_t, proofs: proofs_t }), ty)
            }
            Head::Absurd { ty } => (Rc::new(Term::Absurd { ty: self.q(depth, ty, None), proof: Rc::new(Term::Erased) }), Some(ty.clone())),
            Head::Transport { ty, lhs, rhs, motive, val } => {
                let ty_t = self.q(depth, ty, None);
                let lhs_t = self.q(depth, lhs, Some(ty));
                let rhs_t = self.q(depth, rhs, Some(ty));
                let y = self.fresh(depth, Rel::Rel, ty);
                let motive_t = self.q_under(depth, motive, vec![y], None);
                let val_ty = self.inst_ty(motive, vec![EnvEntry::Rel(lhs.clone())], depth);
                let val_t = self.q(depth, val, val_ty.as_ref());
                let res_ty = self.inst_ty(motive, vec![EnvEntry::Rel(rhs.clone())], depth);
                (
                    Rc::new(Term::Transport { ty: ty_t, lhs: lhs_t, rhs: rhs_t, eq: Rc::new(Term::Erased), motive: motive_t, val: val_t }),
                    res_ty,
                )
            }
            Head::Axiom { ax, args } => {
                let args_t = args.iter().map(|a| self.q_arg(depth, a, None).1).collect();
                let ty = crate::axioms::axiom_type_value(self.env, *ax, args, depth);
                (Rc::new(Term::Axiom { ax: *ax, args: args_t }), ty)
            }
        }
    }

    /// Best-effort type of a value (used for let types when sharing).
    pub fn vtype(&mut self, depth: Lvl, v: &V) -> Option<V> {
        match &**v {
            Value::Lit { w, .. } => Some(Rc::new(Value::IntTy(*w))),
            Value::Ctor { ind, params, .. } => Some(Rc::new(Value::Ind { ind: *ind, params: params.clone() })),
            Value::Refl { ty, val } => Some(Rc::new(Value::Eq { ty: ty.clone(), lhs: val.clone(), rhs: val.clone() })),
            Value::IntTy(_) | Value::Ind { .. } | Value::Eq { .. } | Value::Sigma { .. } => Some(Rc::new(Value::Sort(Sort::Type))),
            Value::Neu(n) => {
                // Reuse the typed neutral walk; discard the term.
                let saved = self.typed;
                self.typed = true;
                let ty = self.neutral_type(depth, n);
                self.typed = saved;
                ty
            }
            _ => None,
        }
    }

    fn neutral_type(&mut self, depth: Lvl, n: &Neutral) -> Option<V> {
        let mut ty = match &n.head {
            Head::Var(l) => self.types.get(l.0 as usize).cloned().flatten(),
            Head::Global { def, args } => {
                let env = self.env;
                let mut ty = env.defs.get(def.0 as usize).map(|d| d.ty_val.clone());
                for a in args {
                    ty = match ty.as_deref() {
                        Some(Value::Pi { cod, .. }) => {
                            let cod = cod.clone();
                            self.inst_ty(&cod, vec![crate::util::arg_entry(a)], depth)
                        }
                        _ => None,
                    };
                }
                ty
            }
            Head::Prim { op, .. } => prim::prim_sig(*op).map(|s| match s.result {
                PrimTy::Int(w) => Rc::new(Value::IntTy(w)),
                PrimTy::Bool => Rc::new(Value::Ind { ind: self.env.bool_id, params: vec![] }),
            }),
            Head::Absurd { ty } => Some(ty.clone()),
            Head::Transport { rhs, motive, .. } => self.inst_ty(motive, vec![EnvEntry::Rel(rhs.clone())], depth),
            Head::Axiom { ax, args } => crate::axioms::axiom_type_value(self.env, *ax, args, depth),
        };
        for (i, e) in n.spine.iter().enumerate() {
            ty = match (e, ty.as_deref()) {
                (Elim::App(a), Some(Value::Pi { cod, .. })) => {
                    let cod = cod.clone();
                    self.inst_ty(&cod, vec![crate::util::arg_entry(a)], depth)
                }
                (Elim::Fst, Some(Value::Sigma { fst, .. })) => Some(fst.clone()),
                (Elim::Snd, Some(Value::Sigma { snd, .. })) => {
                    let snd = snd.clone();
                    let f = self.ev().fst(&prefix_value(n, i));
                    self.inst_ty(&snd, vec![EnvEntry::Rel(f)], depth)
                }
                (Elim::Match { motive, .. }, _) => self.inst_ty(motive, vec![EnvEntry::Rel(prefix_value(n, i))], depth),
                _ => None,
            };
        }
        ty
    }
}

/// If `v` is the eta-expanded form of the array variable at level `l`
/// (`([index(T, fst x, 0), ..], snd x)`, as built by the evaluator), `l`.
fn eta_var(env: &Env, v: &V) -> Option<Lvl> {
    let index = env.known.index?;
    let Value::Pair { fst, snd: Arg::Irr(c) } = &**v else { return None };
    // snd must be the closure `snd(Var 0)` over the variable itself.
    let (Term::Snd(inner), [EnvEntry::Rel(x)]) = (&*c.body, c.env.0.as_slice()) else { return None };
    let (Term::Var(Idx(0)), Value::Neu(Neutral { head: Head::Var(l), spine })) = (&**inner, &**x) else { return None };
    if !spine.is_empty() {
        return None;
    }
    // fst must be the list of `index(T, fst x, k)` for k = 0, 1, ...
    let mut cur = fst.clone();
    let mut k = 0u64;
    loop {
        let next = match &*cur {
            Value::Ctor { args, .. } if args.is_empty() => return Some(*l),
            Value::Ctor { args, .. } if args.len() == 2 => {
                let (Arg::Rel(h), Arg::Rel(t)) = (&args[0], &args[1]) else { return None };
                let Value::Neu(Neutral { head: Head::Global { def, args: ia }, spine }) = &**h else { return None };
                if *def != index || !spine.is_empty() || ia.len() != 5 {
                    return None;
                }
                let (Arg::Rel(lst), Arg::Rel(kv)) = (&ia[1], &ia[2]) else { return None };
                let fst_of_x = matches!(&**lst, Value::Neu(Neutral { head: Head::Var(l2), spine })
                    if l2 == l && spine.len() == 1 && matches!(spine[0], Elim::Fst));
                if !fst_of_x || prim::as_lit(kv).and_then(|n| u64::try_from(n.clone()).ok()) != Some(k) {
                    return None;
                }
                k += 1;
                t.clone()
            }
            _ => return None,
        };
        cur = next;
    }
}

fn hit_parts((k, t, ty): (usize, Tm, Option<V>)) -> (Tm, Option<V>, usize) {
    (t, ty, k)
}

/// The neutral made of `n`'s head and its first `i` eliminators.
fn prefix_value(n: &Neutral, i: usize) -> V {
    neu(clone_head(&n.head), n.spine[..i].iter().map(clone_elim).collect())
}

/// Direct children of a value in the top-level DAG (closures not entered).
fn top_children(v: &V) -> Vec<V> {
    let mut out = Vec::new();
    let rel = |a: &Arg, out: &mut Vec<V>| {
        if let Arg::Rel(x) = a {
            out.push(x.clone());
        }
    };
    match &**v {
        Value::Sort(_) | Value::IntTy(_) | Value::Lit { .. } => {}
        Value::Pi { dom, .. } | Value::Lam { dom, .. } => out.push(dom.clone()),
        Value::Sigma { fst, .. } => out.push(fst.clone()),
        Value::Pair { fst, snd } => {
            out.push(fst.clone());
            rel(snd, &mut out);
        }
        Value::Eq { ty, lhs, rhs } => out.extend([ty.clone(), lhs.clone(), rhs.clone()]),
        Value::Refl { ty, val } => out.extend([ty.clone(), val.clone()]),
        Value::Ind { params, .. } => out.extend(params.iter().cloned()),
        Value::Ctor { params, args, .. } => {
            out.extend(params.iter().cloned());
            for a in args {
                rel(a, &mut out);
            }
        }
        Value::Neu(n) => {
            match &n.head {
                Head::Var(_) => {}
                Head::Global { args, .. } | Head::Axiom { args, .. } => {
                    for a in args {
                        rel(a, &mut out);
                    }
                }
                Head::Prim { args, .. } => out.extend(args.iter().cloned()),
                Head::Absurd { ty } => out.push(ty.clone()),
                Head::Transport { ty, lhs, rhs, val, .. } => out.extend([ty.clone(), lhs.clone(), rhs.clone(), val.clone()]),
            }
            for e in &n.spine {
                match e {
                    Elim::App(a) => rel(a, &mut out),
                    Elim::Match { params, .. } => out.extend(params.iter().cloned()),
                    _ => {}
                }
            }
        }
    }
    out
}

/// Nodes of the top-level DAG of `root` with more than one parent, in
/// post-order (children first), excluding leaves; plus the parent counts.
fn shared_nodes(root: &V) -> (Vec<V>, HashMap<usize, usize>) {
    let mut parents: HashMap<usize, usize> = HashMap::new();
    let mut visited: HashMap<usize, ()> = HashMap::new();
    let mut post: Vec<V> = Vec::new();
    // Iterative DFS: (node, children expanded?)
    let mut stack: Vec<(V, bool)> = vec![(root.clone(), false)];
    visited.insert(addr(root), ());
    while let Some((v, expanded)) = stack.pop() {
        if expanded {
            post.push(v);
            continue;
        }
        let kids = top_children(&v);
        stack.push((v, true));
        for k in kids.into_iter().rev() {
            *parents.entry(addr(&k)).or_insert(0) += 1;
            if visited.insert(addr(&k), ()).is_none() {
                stack.push((k, false));
            }
        }
    }
    let order = post
        .into_iter()
        .filter(|n| parents.get(&addr(n)).copied().unwrap_or(0) > 1 && !top_children(n).is_empty() && !is_leafish(n))
        .collect();
    (order, parents)
}

fn is_leafish(v: &V) -> bool {
    matches!(&**v, Value::Neu(Neutral { head: Head::Var(_), spine }) if spine.is_empty())
}

// The memo's reference tests (memoized vs unmemoized read-back); the file
// lives with the tests so that it does not count towards the TCB's size.
#[cfg(test)]
#[path = "../tests/unit/quote_memo.rs"]
mod memo_tests;
