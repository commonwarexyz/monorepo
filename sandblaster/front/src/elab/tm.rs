//! Core-term utilities for the elaborator (the kernel's generic traversals
//! are crate-private): a post-order map with binder depths, free-variable
//! renaming between contexts (loop-helper facts, §7.4) and a size measure.

use std::collections::HashMap;
use std::rc::Rc;

use sandblaster_kernel::term::{Arm, Idx, Term, Tm};

use crate::auto::util::{FxMap, FxSet};

/// Rebuilds `t` bottom-up; `f` receives each rebuilt node and the number of
/// binders crossed. Returns `None` if `f` does. `f` must be a function of
/// its arguments: shared subterms (the same `Rc` at the same binder depth)
/// are mapped once and stay shared in the result, so the cost is linear in
/// the size of the term *graph* (terms produced by substitution share
/// heavily; as trees they can be exponentially larger).
pub fn map_post(t: &Tm, depth: u32, f: &mut dyn FnMut(Tm, u32) -> Option<Tm>) -> Option<Tm> {
    let mut memo: FxMap<(*const Term, u32), Tm> = FxMap::default();
    map_post_memo(t, depth, f, &mut memo)
}

fn map_post_memo(t: &Tm, depth: u32, f: &mut dyn FnMut(Tm, u32) -> Option<Tm>, memo: &mut FxMap<(*const Term, u32), Tm>) -> Option<Tm> {
    let key = (Rc::as_ptr(t), depth);
    if let Some(r) = memo.get(&key) {
        return Some(r.clone());
    }
    // front-end work of a prover call (no-op elsewhere; auto::meter)
    crate::auto::meter::spend(1);
    let r = map_post_node(t, depth, f, memo)?;
    memo.insert(key, r.clone());
    Some(r)
}

fn map_post_node(t: &Tm, depth: u32, f: &mut dyn FnMut(Tm, u32) -> Option<Tm>, memo: &mut FxMap<(*const Term, u32), Tm>) -> Option<Tm> {
    use Term::*;
    let mut m = |x: &Tm, k: u32, f: &mut dyn FnMut(Tm, u32) -> Option<Tm>| map_post_memo(x, depth + k, f, memo);
    let node: Tm = match &**t {
        Var(_) | Global(_) | Sort(_) | IntTy(_) | Lit { .. } | Erased => t.clone(),
        Pi { name, rel, dom, cod } => Rc::new(Pi { name: name.clone(), rel: *rel, dom: m(dom, 0, f)?, cod: m(cod, 1, f)? }),
        Lam { name, rel, dom, body } => Rc::new(Lam { name: name.clone(), rel: *rel, dom: m(dom, 0, f)?, body: m(body, 1, f)? }),
        App { rel, fun, arg } => Rc::new(App { rel: *rel, fun: m(fun, 0, f)?, arg: m(arg, 0, f)? }),
        Let { name, rel, ty, val, body } => Rc::new(Let { name: name.clone(), rel: *rel, ty: m(ty, 0, f)?, val: m(val, 0, f)?, body: m(body, 1, f)? }),
        Sigma { name, snd_rel, fst, snd } => Rc::new(Sigma { name: name.clone(), snd_rel: *snd_rel, fst: m(fst, 0, f)?, snd: m(snd, 1, f)? }),
        Pair { ty, fst, snd } => Rc::new(Pair { ty: m(ty, 0, f)?, fst: m(fst, 0, f)?, snd: m(snd, 0, f)? }),
        Fst(p) => Rc::new(Fst(m(p, 0, f)?)),
        Snd(p) => Rc::new(Snd(m(p, 0, f)?)),
        Eq { ty, lhs, rhs } => Rc::new(Eq { ty: m(ty, 0, f)?, lhs: m(lhs, 0, f)?, rhs: m(rhs, 0, f)? }),
        Refl { ty, val } => Rc::new(Refl { ty: m(ty, 0, f)?, val: m(val, 0, f)? }),
        Transport { ty, lhs, rhs, eq, motive, val } => Rc::new(Transport { ty: m(ty, 0, f)?, lhs: m(lhs, 0, f)?, rhs: m(rhs, 0, f)?, eq: m(eq, 0, f)?, motive: m(motive, 1, f)?, val: m(val, 0, f)? }),
        Ind { ind, params } => Rc::new(Ind { ind: *ind, params: params.iter().map(|p| m(p, 0, f)).collect::<Option<Vec<_>>>()? }),
        Ctor { ind, ctor, params, args } => Rc::new(Ctor { ind: *ind, ctor: *ctor, params: params.iter().map(|p| m(p, 0, f)).collect::<Option<Vec<_>>>()?, args: args.iter().map(|p| m(p, 0, f)).collect::<Option<Vec<_>>>()? }),
        Match { ind, params, scrut, motive, arms } => Rc::new(Match {
            ind: *ind,
            params: params.iter().map(|p| m(p, 0, f)).collect::<Option<Vec<_>>>()?,
            scrut: m(scrut, 0, f)?,
            motive: m(motive, 1, f)?,
            arms: arms.iter().map(|a| Some(Arm { names: a.names.clone(), body: m(&a.body, a.names.len() as u32, f)? })).collect::<Option<Vec<_>>>()?,
        }),
        Prim { op, args, proofs } => Rc::new(Prim { op: *op, args: args.iter().map(|p| m(p, 0, f)).collect::<Option<Vec<_>>>()?, proofs: proofs.iter().map(|p| m(p, 0, f)).collect::<Option<Vec<_>>>()? }),
        Rec { args, proof } => Rc::new(Rec {
            args: args.iter().map(|p| m(p, 0, f)).collect::<Option<Vec<_>>>()?,
            proof: match proof {
                Some(p) => Some(m(p, 0, f)?),
                None => None,
            },
        }),
        Delta { def, args } => Rc::new(Delta { def: *def, args: args.iter().map(|p| m(p, 0, f)).collect::<Option<Vec<_>>>()? }),
        Unfold { def, args, to_body, val } => Rc::new(Unfold { def: *def, args: args.iter().map(|p| m(p, 0, f)).collect::<Option<Vec<_>>>()?, to_body: *to_body, val: m(val, 0, f)? }),
        Linarith { hyps, goal, cert } => Rc::new(Linarith { hyps: hyps.iter().map(|(p, s)| Some((m(p, 0, f)?, m(s, 0, f)?))).collect::<Option<Vec<_>>>()?, goal: m(goal, 0, f)?, cert: cert.clone() }),
        BvRefl { ty, lhs, rhs } => Rc::new(BvRefl { ty: m(ty, 0, f)?, lhs: m(lhs, 0, f)?, rhs: m(rhs, 0, f)? }),
        Absurd { ty, proof } => Rc::new(Absurd { ty: m(ty, 0, f)?, proof: m(proof, 0, f)? }),
        Axiom { ax, args } => Rc::new(Axiom { ax: *ax, args: args.iter().map(|p| m(p, 0, f)).collect::<Option<Vec<_>>>()? }),
    };
    f(node, depth)
}

/// Renames the free variables of `t` (a term at context depth `from_depth`)
/// through `map` (old level → new level) into a context of depth
/// `to_depth`. `None` if some free variable is not in `map`.
pub fn rename_levels(t: &Tm, from_depth: u32, map: &HashMap<u32, usize>, to_depth: u32) -> Option<Tm> {
    map_post(t, 0, &mut |n, b| match &*n {
        Term::Var(Idx(i)) if *i >= b => {
            let lvl = from_depth.checked_sub(1 + (*i - b))?;
            let nl = *map.get(&lvl)? as u32;
            Some(Rc::new(Term::Var(Idx(to_depth - 1 - nl + b))))
        }
        _ => Some(n),
    })
}

/// Visits every distinct node of the term graph (by `Rc` identity) until
/// `f` returns `true`; returns whether it did.
pub fn any_node(t: &Tm, f: &mut dyn FnMut(&Term) -> bool) -> bool {
    fn go(t: &Tm, f: &mut dyn FnMut(&Term) -> bool, seen: &mut FxSet<*const Term>) -> bool {
        if !seen.insert(Rc::as_ptr(t)) {
            return false;
        }
        crate::auto::meter::spend(1);
        if f(t) {
            return true;
        }
        let mut found = false;
        children(t, &mut |c| {
            if !found && go(c, f, seen) {
                found = true;
            }
        });
        found
    }
    go(t, f, &mut FxSet::default())
}

/// Like [`any_node`], with the number of binders crossed: visits every
/// distinct (node, binder depth) pair until `f` returns `true`.
pub fn any_node_depth(t: &Tm, f: &mut dyn FnMut(&Term, u32) -> bool) -> bool {
    fn go(t: &Tm, b: u32, f: &mut dyn FnMut(&Term, u32) -> bool, seen: &mut FxSet<(*const Term, u32)>) -> bool {
        if !seen.insert((Rc::as_ptr(t), b)) {
            return false;
        }
        crate::auto::meter::spend(1);
        if f(t, b) {
            return true;
        }
        let mut found = false;
        children_depth(t, &mut |c, k| {
            if !found && go(c, b + k, f, seen) {
                found = true;
            }
        });
        found
    }
    go(t, 0, f, &mut FxSet::default())
}

/// Calls `f` on each direct subterm with the number of binders it is under
/// (relative to `t`).
pub fn children_depth(t: &Tm, f: &mut dyn FnMut(&Tm, u32)) {
    use Term::*;
    match &**t {
        Var(_) | Global(_) | Sort(_) | IntTy(_) | Lit { .. } | Erased => {}
        Pi { dom, cod: b, .. } | Lam { dom, body: b, .. } | Sigma { fst: dom, snd: b, .. } => {
            f(dom, 0);
            f(b, 1);
        }
        Let { ty, val, body, .. } => {
            f(ty, 0);
            f(val, 0);
            f(body, 1);
        }
        Transport { ty, lhs, rhs, eq, motive, val } => {
            f(ty, 0);
            f(lhs, 0);
            f(rhs, 0);
            f(eq, 0);
            f(motive, 1);
            f(val, 0);
        }
        Match { params, scrut, motive, arms, .. } => {
            params.iter().for_each(|p| f(p, 0));
            f(scrut, 0);
            f(motive, 1);
            for a in arms {
                f(&a.body, a.names.len() as u32);
            }
        }
        _ => children(t, &mut |c| f(c, 0)),
    }
}

/// Calls `f` on each direct subterm.
pub fn children(t: &Tm, f: &mut dyn FnMut(&Tm)) {
    use Term::*;
    match &**t {
        Var(_) | Global(_) | Sort(_) | IntTy(_) | Lit { .. } | Erased => {}
        Pi { dom, cod: b, .. } | Lam { dom, body: b, .. } | Sigma { fst: dom, snd: b, .. } => {
            f(dom);
            f(b);
        }
        App { fun, arg, .. } => {
            f(fun);
            f(arg);
        }
        Let { ty, val, body, .. } => {
            f(ty);
            f(val);
            f(body);
        }
        Pair { ty, fst, snd } => {
            f(ty);
            f(fst);
            f(snd);
        }
        Fst(p) | Snd(p) => f(p),
        Eq { ty, lhs, rhs } | BvRefl { ty, lhs, rhs } => {
            f(ty);
            f(lhs);
            f(rhs);
        }
        Refl { ty, val } => {
            f(ty);
            f(val);
        }
        Transport { ty, lhs, rhs, eq, motive, val } => {
            for x in [ty, lhs, rhs, eq, motive, val] {
                f(x);
            }
        }
        Ind { params, .. } => params.iter().for_each(f),
        Ctor { params, args, .. } => params.iter().chain(args).for_each(f),
        Match { params, scrut, motive, arms, .. } => {
            params.iter().for_each(&mut *f);
            f(scrut);
            f(motive);
            arms.iter().for_each(|a| f(&a.body));
        }
        Prim { args, proofs, .. } => args.iter().chain(proofs).for_each(f),
        Rec { args, proof } => {
            args.iter().for_each(&mut *f);
            if let Some(p) = proof {
                f(p);
            }
        }
        Delta { args, .. } | Axiom { args, .. } => args.iter().for_each(f),
        Unfold { args, val, .. } => {
            args.iter().for_each(&mut *f);
            f(val);
        }
        Linarith { hyps, goal, .. } => {
            for (p, s) in hyps {
                f(p);
                f(s);
            }
            f(goal);
        }
        Absurd { ty, proof } => {
            f(ty);
            f(proof);
        }
    }
}

/// Number of distinct nodes of the term graph, counting up to `cap` (for
/// budgets and heuristics).
pub fn size_capped(t: &Tm, cap: usize) -> usize {
    let mut n = 0usize;
    any_node(t, &mut |_| {
        n += 1;
        n >= cap
    });
    n
}

/// Number of distinct nodes of the term graph.
pub fn size(t: &Tm) -> usize {
    size_capped(t, usize::MAX)
}

/// Instantiates a term closed over a telescope of `args.len()` binders
/// (level `i` ↦ `args[i]`, all at the same depth): `t` is at depth
/// `args.len()` (no other free variables); the result is at the depth of
/// the arguments.
pub fn subst_closed(t: &Tm, args: &[Tm]) -> Tm {
    let n = args.len() as u32;
    map_post(t, 0, &mut |node, b| match &*node {
        Term::Var(Idx(i)) if *i >= b => {
            let lvl = n.checked_sub(1 + (*i - b))?;
            Some(sandblaster_kernel::util::shift(&args[lvl as usize], b as i64))
        }
        _ => Some(node),
    })
    .expect("subst_closed: term not closed over the telescope")
}

/// Whether `t` contains a `Linarith` node.
pub fn has_linarith(t: &Tm) -> bool {
    any_node(t, &mut |x| matches!(x, Term::Linarith { .. }))
}

/// Whether `t` contains `Erased`.
pub fn has_erased(t: &Tm) -> bool {
    any_node(t, &mut |x| matches!(x, Term::Erased))
}

/// `t[Var(0) := v]` for a term `t` in a context extended by one variable
/// (`v` in the base context): the variable is replaced and the others are
/// shifted down.
pub fn subst0(t: &Tm, v: &Tm) -> Tm {
    map_post(t, 0, &mut |node, b| match &*node {
        Term::Var(Idx(i)) if *i == b => Some(sandblaster_kernel::util::shift(v, b as i64)),
        Term::Var(Idx(i)) if *i > b => Some(Rc::new(Term::Var(Idx(*i - 1)))),
        _ => Some(node),
    })
    .expect("subst0")
}

/// `t[Var(k) := v]`: replaces the free variable of index `k` (at the root
/// of `t`) by `v` (a term in the context without that variable, at the
/// root of `t` — so it may mention the `k` variables bound after it) and
/// shifts the variables above it down by one.
pub fn subst_idx(t: &Tm, k: u32, v: &Tm) -> Tm {
    map_post(t, 0, &mut |node, b| match &*node {
        Term::Var(Idx(i)) if *i == b + k => Some(sandblaster_kernel::util::shift(v, b as i64)),
        Term::Var(Idx(i)) if *i > b + k => Some(Rc::new(Term::Var(Idx(*i - 1)))),
        _ => Some(node),
    })
    .expect("subst_idx")
}

/// Rebuilds `t` with each direct subterm mapped by `m`, which receives the
/// subterm and the number of binders it is under (relative to `t`).
pub fn rebuild(t: &Tm, m: &mut dyn FnMut(&Tm, u32) -> Tm) -> Tm {
    use Term::*;
    let v = |xs: &[Tm], m: &mut dyn FnMut(&Tm, u32) -> Tm| xs.iter().map(|x| m(x, 0)).collect::<Vec<_>>();
    match &**t {
        Var(_) | Global(_) | Sort(_) | IntTy(_) | Lit { .. } | Erased => t.clone(),
        Pi { name, rel, dom, cod } => Rc::new(Pi { name: name.clone(), rel: *rel, dom: m(dom, 0), cod: m(cod, 1) }),
        Lam { name, rel, dom, body } => Rc::new(Lam { name: name.clone(), rel: *rel, dom: m(dom, 0), body: m(body, 1) }),
        App { rel, fun, arg } => Rc::new(App { rel: *rel, fun: m(fun, 0), arg: m(arg, 0) }),
        Let { name, rel, ty, val, body } => Rc::new(Let { name: name.clone(), rel: *rel, ty: m(ty, 0), val: m(val, 0), body: m(body, 1) }),
        Sigma { name, snd_rel, fst, snd } => Rc::new(Sigma { name: name.clone(), snd_rel: *snd_rel, fst: m(fst, 0), snd: m(snd, 1) }),
        Pair { ty, fst, snd } => Rc::new(Pair { ty: m(ty, 0), fst: m(fst, 0), snd: m(snd, 0) }),
        Fst(p) => Rc::new(Fst(m(p, 0))),
        Snd(p) => Rc::new(Snd(m(p, 0))),
        Eq { ty, lhs, rhs } => Rc::new(Eq { ty: m(ty, 0), lhs: m(lhs, 0), rhs: m(rhs, 0) }),
        Refl { ty, val } => Rc::new(Refl { ty: m(ty, 0), val: m(val, 0) }),
        Transport { ty, lhs, rhs, eq, motive, val } => Rc::new(Transport { ty: m(ty, 0), lhs: m(lhs, 0), rhs: m(rhs, 0), eq: m(eq, 0), motive: m(motive, 1), val: m(val, 0) }),
        Ind { ind, params } => Rc::new(Ind { ind: *ind, params: v(params, m) }),
        Ctor { ind, ctor, params, args } => Rc::new(Ctor { ind: *ind, ctor: *ctor, params: v(params, m), args: v(args, m) }),
        Match { ind, params, scrut, motive, arms } => Rc::new(Match {
            ind: *ind,
            params: v(params, m),
            scrut: m(scrut, 0),
            motive: m(motive, 1),
            arms: arms.iter().map(|a| Arm { names: a.names.clone(), body: m(&a.body, a.names.len() as u32) }).collect(),
        }),
        Prim { op, args, proofs } => Rc::new(Prim { op: *op, args: v(args, m), proofs: v(proofs, m) }),
        Rec { args, proof } => Rc::new(Rec { args: v(args, m), proof: proof.as_ref().map(|p| m(p, 0)) }),
        Delta { def, args } => Rc::new(Delta { def: *def, args: v(args, m) }),
        Unfold { def, args, to_body, val } => Rc::new(Unfold { def: *def, args: v(args, m), to_body: *to_body, val: m(val, 0) }),
        Linarith { hyps, goal, cert } => Rc::new(Linarith { hyps: hyps.iter().map(|(p, s)| (m(p, 0), m(s, 0))).collect(), goal: m(goal, 0), cert: cert.clone() }),
        BvRefl { ty, lhs, rhs } => Rc::new(BvRefl { ty: m(ty, 0), lhs: m(lhs, 0), rhs: m(rhs, 0) }),
        Absurd { ty, proof } => Rc::new(Absurd { ty: m(ty, 0), proof: m(proof, 0) }),
        Axiom { ax, args } => Rc::new(Axiom { ax: *ax, args: v(args, m) }),
    }
}

/// Rebuilds `t` top-down: `f` sees each node (and the number of binders
/// crossed) before its subterms and may replace it (`Some`), which stops
/// the descent there. Shared subterms at the same binder depth are mapped
/// once (the input is kept alive by the caller for the whole call, so the
/// memo's addresses stay valid).
pub fn map_pre(t: &Tm, depth: u32, f: &mut dyn FnMut(&Tm, u32) -> Option<Tm>) -> Tm {
    fn go(t: &Tm, d: u32, f: &mut dyn FnMut(&Tm, u32) -> Option<Tm>, memo: &mut HashMap<(*const Term, u32), Tm>) -> Tm {
        let key = (Rc::as_ptr(t), d);
        if let Some(r) = memo.get(&key) {
            return r.clone();
        }
        crate::auto::meter::spend(1);
        let r = match f(t, d) {
            Some(r) => r,
            None => rebuild(t, &mut |c, k| go(c, d + k, f, memo)),
        };
        memo.insert(key, r.clone());
        r
    }
    go(t, depth, f, &mut HashMap::new())
}

/// Syntactic generalization (script steps on goal *terms*, §4.4): the
/// motive `t[target := y]` — a term at depth `d + 1` whose `Var(0)` is `y`
/// — replacing every subterm of `t` (a term at depth `d`) that equals
/// `target` (at depth `d`) up to binder names and proofs
/// ([`Env::alpha_eq_relevant`](sandblaster_kernel::api::Env::alpha_eq_relevant)).
/// Occurrences mentioning variables bound inside `t` are not abstracted.
/// `None` if there is no occurrence.
///
/// Goals mentioning large transparent functions have huge *values* (the
/// evaluator unfolds them), so generalizing through a quoted value is
/// impractical; the goal term keeps calls folded and stays small.
pub fn abstract_syntactic(env: &sandblaster_kernel::api::Env, t: &Tm, target: &Tm) -> Option<Tm> {
    let mut found = false;
    let mut targets: HashMap<u32, Tm> = HashMap::new();
    let head = |x: &Tm| -> Option<sandblaster_kernel::term::GlobalId> {
        let mut h = x;
        while let Term::App { fun, .. } = &**h {
            h = fun;
        }
        match &**h {
            Term::Global(g) => Some(*g),
            _ => None,
        }
    };
    let thead = head(target);
    let tkind = std::mem::discriminant(&**target);
    let m = map_pre(t, 0, &mut |n, k| {
        if let Term::Var(Idx(i)) = &**n {
            return Some(if *i >= k { Rc::new(Term::Var(Idx(*i + 1))) } else { n.clone() });
        }
        if std::mem::discriminant(&**n) == tkind && head(n) == thead {
            let tk = targets.entry(k).or_insert_with(|| sandblaster_kernel::util::shift(target, k as i64)).clone();
            if Rc::ptr_eq(n, &tk) || env.alpha_eq_relevant(n, &tk, &|a, b| a == b) {
                found = true;
                return Some(Rc::new(Term::Var(Idx(k))));
            }
        }
        None
    });
    found.then_some(m)
}

/// `t` with its relevant `let`s put in (ζ; convertible with `t`): the
/// goal of an unfolded exec function names intermediate values (`let s01 =
/// ..; s01.split_first_chunk::<32>()`) that a script's scrutinee (`s0.
/// split_first_chunk::<32>()`) spells out. Irrelevant `let`s (facts) stay.
pub fn zeta_relevant(t: &Tm) -> Tm {
    fn go(t: &Tm, memo: &mut HashMap<*const Term, (Tm, Tm)>) -> Tm {
        if let Some((_, r)) = memo.get(&Rc::as_ptr(t)) {
            return r.clone();
        }
        crate::auto::meter::spend(1);
        let r = match &**t {
            Term::Let { rel: sandblaster_kernel::term::Rel::Rel, val, body, .. } => {
                let v = go(val, memo);
                let b = go(body, memo);
                subst0(&b, &v)
            }
            _ => rebuild(t, &mut |c, _| go(c, memo)),
        };
        memo.insert(Rc::as_ptr(t), (t.clone(), r.clone()));
        r
    }
    go(t, &mut HashMap::new())
}

/// Contracts the redexes a term-level substitution creates (script goals,
/// §4.4): `match C(a..) { .. }` (ι), `(λx. b) a` (β), `fst/snd` of a pair.
/// Nothing is evaluated; the result is convertible with the input.
pub fn simp_redexes(t: &Tm) -> Tm {
    // memo by address; the input of every entry is kept alive in the entry
    // (intermediate terms are created and dropped during the walk)
    fn go(t: &Tm, memo: &mut HashMap<*const Term, (Tm, Tm)>) -> Tm {
        if let Some((_, r)) = memo.get(&Rc::as_ptr(t)) {
            return r.clone();
        }
        crate::auto::meter::spend(1);
        let r = match &**t {
            Term::Match { scrut, arms, .. } => {
                let s = go(scrut, memo);
                match &*s {
                    Term::Ctor { ctor, args, .. } if (*ctor as usize) < arms.len() && arms[*ctor as usize].names.len() == args.len() => {
                        // the fields are the arm's last binders (the last
                        // field is `Var(0)`); substitute from the last one,
                        // each argument shifted over the fields still bound
                        let mut b = arms[*ctor as usize].body.clone();
                        for (i, a) in args.iter().enumerate().rev() {
                            b = subst0(&b, &sandblaster_kernel::util::shift(a, i as i64));
                        }
                        go(&b, memo)
                    }
                    _ => rebuild(t, &mut |c, _| go(c, memo)),
                }
            }
            Term::App { fun, arg, .. } => {
                let f = go(fun, memo);
                match &*f {
                    Term::Lam { body, .. } => {
                        let a = go(arg, memo);
                        go(&subst0(body, &a), memo)
                    }
                    _ => rebuild(t, &mut |c, _| go(c, memo)),
                }
            }
            Term::Fst(p) | Term::Snd(p) => {
                let q = go(p, memo);
                match (&**t, &*q) {
                    (Term::Fst(_), Term::Pair { fst, .. }) => fst.clone(),
                    (Term::Snd(_), Term::Pair { snd, .. }) => snd.clone(),
                    _ => rebuild(t, &mut |c, _| go(c, memo)),
                }
            }
            _ => rebuild(t, &mut |c, _| go(c, memo)),
        };
        memo.insert(Rc::as_ptr(t), (t.clone(), r.clone()));
        r
    }
    go(t, &mut HashMap::new())
}

/// Term-level unfolding of a transparent, non-recursive definition `g`
/// (script `unfold(f)`, §4.4): every full application `g a..` in `t` is
/// replaced by `g`'s body instantiated with the arguments (convertible with
/// it). `None` if `g` is opaque or recursive, or does not occur applied.
pub fn unfold_syntactic(env: &sandblaster_kernel::api::Env, t: &Tm, g: sandblaster_kernel::term::GlobalId) -> Option<Tm> {
    let (inner, arity) = transparent_body(env, g)?;
    let mut found = false;
    let mut cur = t.clone();
    // nested applications (in the arguments of an unfolded one) are
    // reached by repeating the pass
    for _ in 0..8 {
        let mut hit = false;
        let next = map_pre(&cur, 0, &mut |n, _| {
            let (h, args) = crate::elab::items::spine(n);
            if args.len() == arity && matches!(&*h, Term::Global(x) if *x == g) {
                hit = true;
                return Some(subst_closed(&inner, &args));
            }
            None
        });
        if !hit {
            break;
        }
        found = true;
        cur = next;
    }
    found.then_some(cur)
}

/// The body of a transparent, non-recursive definition with its telescope's
/// lambdas peeled (a term at depth `arity`), and the arity.
fn transparent_body(env: &sandblaster_kernel::api::Env, g: sandblaster_kernel::term::GlobalId) -> Option<(Tm, usize)> {
    if env.global_opaque(g) != Some(false) {
        return None;
    }
    let body = env.global_body(g)?;
    // committed bodies call themselves through the global (`Rec` replaced)
    if any_node(&body, &mut |x| matches!(x, Term::Rec { .. }) || matches!(x, Term::Global(h) if *h == g)) {
        return None;
    }
    let arity = env.global_arity(g)? as usize;
    let mut inner = body;
    for _ in 0..arity {
        let Term::Lam { body, .. } = &*inner.clone() else { return None };
        inner = body.clone();
    }
    Some((inner, arity))
}

/// Head normalization of a goal *term* without evaluation: contracts
/// redexes and top-level `let`s and unfolds transparent non-recursive
/// definitions at the head until `pred` holds (at most a few steps).
pub fn head_unfold(env: &sandblaster_kernel::api::Env, t: &Tm, pred: &dyn Fn(&Term) -> bool) -> Option<Tm> {
    let mut t = simp_redexes(t);
    for _ in 0..16 {
        if pred(&t) {
            return Some(t);
        }
        t = match &*t {
            Term::Let { val, body, .. } => simp_redexes(&subst0(body, val)),
            _ => {
                let (h, args) = crate::elab::items::spine(&t);
                let Term::Global(g) = &*h else { return None };
                let (inner, arity) = transparent_body(env, *g)?;
                if args.len() != arity {
                    return None;
                }
                simp_redexes(&subst_closed(&inner, &args))
            }
        };
    }
    None
}

/// A structural fingerprint of a term (binder names ignored), linear in the
/// term graph: equal terms have equal fingerprints. Used as a cheap
/// deduplication key by the provers (instead of printing terms, which is
/// exponential on shared graphs); a collision can only drop a heuristic
/// candidate.
pub fn fingerprint(t: &Tm) -> u64 {
    fn go(t: &Tm, memo: &mut HashMap<*const Term, u64>) -> u64 {
        use std::hash::{Hash, Hasher};
        if let Some(h) = memo.get(&Rc::as_ptr(t)) {
            return *h;
        }
        crate::auto::meter::spend(1);
        let mut kids: Vec<Tm> = Vec::new();
        children(t, &mut |c| kids.push(c.clone()));
        let mut h = std::collections::hash_map::DefaultHasher::new();
        std::mem::discriminant(&**t).hash(&mut h);
        match &**t {
            Term::Var(i) => i.hash(&mut h),
            Term::Global(g) => g.hash(&mut h),
            Term::Sort(s) => s.hash(&mut h),
            Term::Pi { rel, .. } | Term::Lam { rel, .. } | Term::App { rel, .. } | Term::Let { rel, .. } | Term::Sigma { snd_rel: rel, .. } => rel.hash(&mut h),
            Term::Ind { ind, .. } => ind.hash(&mut h),
            Term::Ctor { ind, ctor, params, .. } => (ind, ctor, params.len()).hash(&mut h),
            Term::Match { ind, params, arms, .. } => (ind, params.len(), arms.iter().map(|a| a.names.len()).collect::<Vec<_>>()).hash(&mut h),
            Term::IntTy(w) => w.hash(&mut h),
            Term::Lit { w, n } => (w, n).hash(&mut h),
            Term::Prim { op, args, .. } => (op, args.len()).hash(&mut h),
            Term::Rec { args, proof } => (args.len(), proof.is_some()).hash(&mut h),
            Term::Delta { def, .. } => def.hash(&mut h),
            Term::Unfold { def, to_body, args, .. } => (def, to_body, args.len()).hash(&mut h),
            Term::Linarith { cert, hyps, .. } => (cert, hyps.len()).hash(&mut h),
            Term::Axiom { ax, .. } => ax.hash(&mut h),
            _ => {}
        }
        for k in &kids {
            go(k, memo).hash(&mut h);
        }
        let r = h.finish();
        memo.insert(Rc::as_ptr(t), r);
        r
    }
    go(t, &mut HashMap::new())
}

/// `Eq(D, C(ps; x̄, p̄), C(ps; ȳ, q̄))` from `eqs[k] : Eq(Aₖ, xₖ, yₖ)` for
/// the relevant fields of constructor `ci` of `ind` (all terms at one
/// depth; `p̄`, `q̄` its `Irr` fields — a struct's invariant, DESIGN.md
/// §15.3): transports along each equation of `Π(r̄ :Irr I(y₀..yₖ₋₁, z,
/// xₖ₊₁..)). Eq(D, C(x̄, p̄), C(y₀..yₖ₋₁, z, xₖ₊₁.., r̄))` — the `Irr` fields
/// generalized, since their types change with the relevant fields —
/// starting from `λr̄. refl` (conversion skips `Irr` constructor fields),
/// applied to `q̄` at the end. `None` for an unknown inductive.
#[allow(clippy::too_many_arguments)]
pub fn ctor_congruence_term(env: &sandblaster_kernel::api::Env, ind: sandblaster_kernel::term::IndId, ci: u32, params: &[Tm], xs: &[Tm], ys: &[Tm], ps: &[Tm], qs: &[Tm], eqs: &[Tm]) -> Option<Tm> {
    use sandblaster_kernel::term::Rel;
    use sandblaster_kernel::util::{mk, shift};
    let decl = env.inductive_decl(ind)?;
    let c = decl.ctors.get(ci as usize)?;
    let n = xs.len();
    let m = c.fields.len().checked_sub(n)?;
    let dty = mk::ind(ind, params.to_vec());
    let lhs = mk::ctor(ind, ci, params.to_vec(), xs.iter().chain(ps).cloned().collect());
    let generalized = |ws: &[Tm], sh: i64| -> Tm {
        let ps2: Vec<Tm> = params.iter().map(|p| shift(p, sh)).collect();
        let mut doms = Vec::new();
        for j in 0..m {
            let mut args: Vec<Tm> = ps2.iter().map(|p| shift(p, j as i64)).collect();
            args.extend(ws.iter().map(|w| shift(w, j as i64)));
            args.extend((0..j as u32).rev().map(mk::var));
            doms.push(subst_closed(&c.fields[n + j].2, &args));
        }
        let mut rargs: Vec<Tm> = ws.iter().map(|w| shift(w, m as i64)).collect();
        rargs.extend((0..m as u32).rev().map(mk::var));
        let mut body = mk::eq(shift(&dty, sh + m as i64), shift(&lhs, sh + m as i64), mk::ctor(ind, ci, ps2.iter().map(|p| shift(p, m as i64)).collect(), rargs));
        for j in (0..m).rev() {
            body = mk::pi("r", Rel::Irr, doms[j].clone(), body);
        }
        body
    };
    let refl_ty = generalized(xs, 0);
    let mut acc = shift(&mk::refl(dty.clone(), lhs.clone()), m as i64);
    {
        let mut t = refl_ty;
        let mut doms = Vec::new();
        for _ in 0..m {
            let Term::Pi { dom, cod, .. } = &*t.clone() else { break };
            doms.push(dom.clone());
            t = cod.clone();
        }
        for d in doms.into_iter().rev() {
            acc = mk::lam("r", Rel::Irr, d, acc);
        }
    }
    for k in 0..n {
        let fty = subst_closed(&c.fields[k].2, &params.iter().cloned().chain(xs[..k].iter().cloned()).collect::<Vec<_>>());
        let mut ws: Vec<Tm> = ys[..k].iter().map(|y| shift(y, 1)).collect();
        ws.push(mk::var(0));
        ws.extend(xs[k + 1..].iter().map(|x| shift(x, 1)));
        let motive = generalized(&ws, 1);
        acc = Rc::new(Term::Transport { ty: fty, lhs: xs[k].clone(), rhs: ys[k].clone(), eq: eqs.get(k)?.clone(), motive, val: acc });
    }
    Some(mk::apps(acc, qs.iter().map(|q| (Rel::Irr, q.clone()))))
}

/// `body` (with `n` innermost binders) instantiated with `args` (terms at
/// the outer depth; `args[0]` for the outermost of the `n`).
pub fn subst_n(body: &Tm, args: &[Tm]) -> Tm {
    let n = args.len() as u32;
    crate::auto::util::map_term(body, 0, &mut |t, k| match &**t {
        Term::Var(Idx(i)) if *i >= k && *i < k + n => Some(crate::auto::util::shift(&args[(n - 1 - (i - k)) as usize], k as i64)),
        Term::Var(Idx(i)) if *i >= k + n => Some(Rc::new(Term::Var(Idx(i - n)))),
        _ => None,
    })
}

/// Head ι/β-reduction of a term: `(match Cₖ(ā) .. with arms) p`
/// becomes arm `k` at `ā` applied to `p`, then `(λe. b) p` becomes
/// `b[e := p]`.
pub fn head_reduce(t: &Tm) -> Tm {
    let mut t = t.clone();
    for _ in 0..8 {
        let next = match &*t {
            Term::App { fun, arg, .. } => match &**fun {
                Term::Match { scrut, arms, .. } => match &**scrut {
                    Term::Ctor { ctor, args, .. } => {
                        let Some(arm) = arms.get(*ctor as usize) else { return t };
                        let b = subst_n(&arm.body, args);
                        Rc::new(Term::App { rel: sandblaster_kernel::term::Rel::Irr, fun: b, arg: arg.clone() })
                    }
                    _ => return t,
                },
                Term::Lam { body, .. } => crate::auto::util::subst0(body, arg),
                _ => return t,
            },
            Term::Match { scrut, arms, .. } => match &**scrut {
                Term::Ctor { ctor, args, .. } => {
                    let Some(arm) = arms.get(*ctor as usize) else { return t };
                    subst_n(&arm.body, args)
                }
                _ => return t,
            },
            _ => return t,
        };
        t = next;
    }
    t
}
