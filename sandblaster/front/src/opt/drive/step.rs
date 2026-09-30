//! Value-level operations of the driver (optimizer design §6.1–§6.3): the
//! head of a value, closure instantiation, elimination of a value by a
//! spine, unfolding of a folded global application, and the
//! static-measure / static-structure tests of design §6.2.
//!
//! These mirror the kernel evaluator's own reductions (which are private to
//! the kernel) using its public entry points: every closure is instantiated
//! with `Env::eval_opaque`, so the values the driver computes are exactly
//! the kernel's. The driver is untrusted: a mistake here only makes the
//! equality lemma fail to check, and the function falls back.

use std::rc::Rc;

use num_traits::ToPrimitive;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, IndId, Lvl, Term};
use sandblaster_kernel::value::{Arg, Budget, Closure, Elim, EnvEntry, Head, Neutral, V, VEnv, Value};

use crate::auto::util::{arg_entry, clone_elim, clone_head, prefix};

/// The shape of a value's head (see [`head_of`]).
pub enum HeadKind<'a> {
    /// The value is (or eliminates) a folded application of a global:
    /// `def args` followed by `elims` (the whole spine of the neutral).
    Folded { def: GlobalId, args: &'a [Arg], app: V, elims: &'a [Elim] },
    /// The value is stuck on a match: `scrut` is the spine prefix before
    /// the first `Match` eliminator, `index` its position.
    Stuck { scrut: V, ind: IndId, params: &'a [V], arms: &'a [Closure], rest: &'a [Elim] },
    /// Anything else (a constructor, a literal, a primitive, a variable, a
    /// pair, …): a straight-line value at the head.
    Other,
}

/// The head of `v`: a folded global application at the head of a neutral
/// (before any match), else the first stuck match of its spine.
pub fn head_of(v: &V) -> HeadKind<'_> {
    let Value::Neu(n) = &**v else { return HeadKind::Other };
    let first_match = n.spine.iter().position(|e| matches!(e, Elim::Match { .. }));
    if let Head::Global { def, args } = &n.head {
        return HeadKind::Folded { def: *def, args, app: prefix(n, 0), elims: &n.spine };
    }
    match first_match {
        Some(i) => {
            let Elim::Match { ind, params, arms, .. } = &n.spine[i] else { unreachable!() };
            HeadKind::Stuck { scrut: prefix(n, i), ind: *ind, params, arms, rest: &n.spine[i + 1..] }
        }
        None => HeadKind::Other,
    }
}

/// The first stuck match of a neutral whose head is a folded global kept
/// by the driver (the scrutinee is then the call's result, eliminated by
/// the spine prefix).
pub fn stuck_after_head(v: &V) -> Option<(V, IndId, &[V], &[Closure], &[Elim])> {
    let Value::Neu(n) = &**v else { return None };
    let i = n.spine.iter().position(|e| matches!(e, Elim::Match { .. }))?;
    let Elim::Match { ind, params, arms, .. } = &n.spine[i] else { unreachable!() };
    Some((prefix(n, i), *ind, params, arms, &n.spine[i + 1..]))
}

/// Evaluation in the driver's mode: the kernel's transparent evaluation
/// with the driver's opaque set.
pub struct Eval<'a> {
    pub env: &'a Env,
    pub opaque: &'a dyn Fn(GlobalId) -> bool,
}

impl Eval<'_> {
    /// `c` instantiated with `es` at context depth `depth`.
    pub fn inst(&self, c: &Closure, es: Vec<EnvEntry>, depth: u32, b: &mut Budget) -> Result<V, String> {
        let mut v = (*c.env.0).clone();
        v.extend(es);
        self.env.eval_opaque(&VEnv(Rc::new(v)), Lvl(depth), &c.body, self.opaque, b).map_err(|e| format!("evaluation: {e:?}"))
    }

    /// Eliminates `v` by `e` (β for an application of a λ, projections of a
    /// pair, ι for a match on a constructor; a neutral gets `e` appended).
    pub fn elim(&self, v: V, e: &Elim, depth: u32, b: &mut Budget) -> Result<V, String> {
        if b.steps == 0 {
            return Err("the driver's step budget is exhausted".into());
        }
        b.steps -= 1;
        match (e, &*v) {
            (Elim::App(a), Value::Lam { body, .. }) => self.inst(body, vec![arg_entry(a)], depth, b),
            (Elim::Fst, Value::Pair { fst, .. }) => Ok(fst.clone()),
            (Elim::Snd, Value::Pair { snd: Arg::Rel(x), .. }) => Ok(x.clone()),
            (Elim::Match { arms, .. }, Value::Ctor { ctor, args, .. }) => {
                let arm = arms.get(*ctor as usize).ok_or("a match without the constructor's arm")?;
                self.inst(arm, args.iter().map(arg_entry).collect(), depth, b)
            }
            (_, Value::Neu(n)) => {
                let mut spine: Vec<Elim> = n.spine.iter().map(clone_elim).collect();
                spine.push(clone_elim(e));
                Ok(Rc::new(Value::Neu(Neutral { head: clone_head(&n.head), spine })))
            }
            _ => Err("an eliminator applied to a value of the wrong shape".into()),
        }
    }

    /// Eliminates `v` by every eliminator of `es` in order.
    pub fn elims(&self, mut v: V, es: &[Elim], depth: u32, b: &mut Budget) -> Result<V, String> {
        for e in es {
            v = self.elim(v, e, depth, b)?;
        }
        Ok(v)
    }

    /// The body of `def` instantiated with `args` (a full application):
    /// what `Delta(def; args)` equates `def args` with.
    pub fn unfold(&self, def: GlobalId, args: &[Arg], depth: u32, b: &mut Budget) -> Result<V, String> {
        let arity = self.env.global_arity(def).ok_or("unknown global")? as usize;
        if args.len() != arity {
            return Err("a partial application".into());
        }
        let mut body = self.env.global_body(def).ok_or("no body")?;
        for _ in 0..arity {
            body = match &*body {
                Term::Lam { body, .. } => body.clone(),
                _ => return Err("a body without its parameter λs".into()),
            };
        }
        let es: Vec<EnvEntry> = args.iter().map(arg_entry).collect();
        self.env.eval_opaque(&VEnv(Rc::new(es)), Lvl(depth), &body, self.opaque, b).map_err(|e| format!("unfolding: {e:?}"))
    }
}

/// A literal machine integer (or `Int`) value.
pub fn as_lit(v: &V) -> Option<num_bigint::BigInt> {
    match &**v {
        Value::Lit { n, .. } => Some(n.clone()),
        _ => None,
    }
}

/// The relevant value of an argument.
pub fn rel(a: &Arg) -> Option<&V> {
    match a {
        Arg::Rel(v) => Some(v),
        Arg::Irr(_) => None,
    }
}

/// `v` is a finite constructor spine of the (recursive) inductive `list`:
/// every recursive field is, transitively, a constructor (the elements may
/// be symbolic). Bounded by `max` constructors.
pub fn closed_spine(v: &V, list: IndId, max: usize) -> bool {
    let mut cur = v.clone();
    for _ in 0..max {
        let next = match &*cur {
            Value::Ctor { ind, ctor: 0, .. } if *ind == list => return true,
            Value::Ctor { ind, ctor: 1, args, .. } if *ind == list => match args.get(1) {
                Some(Arg::Rel(t)) => t.clone(),
                _ => return false,
            },
            _ => return false,
        };
        cur = next;
    }
    false
}

/// The length of a closed spine.
pub fn spine_len(v: &V, list: IndId) -> Option<usize> {
    let mut cur = v.clone();
    let mut n = 0usize;
    loop {
        let next = match &*cur {
            Value::Ctor { ind, ctor: 0, .. } if *ind == list => return Some(n),
            Value::Ctor { ind, ctor: 1, args, .. } if *ind == list => match args.get(1) {
                Some(Arg::Rel(t)) => t.clone(),
                _ => return None,
            },
            _ => return None,
        };
        n += 1;
        if n > 1 << 16 {
            return None;
        }
        cur = next;
    }
}

/// A literal `u64` of a value.
pub fn lit_u64(v: &V) -> Option<u64> {
    as_lit(v).and_then(|n| n.to_u64())
}

/// Whether `v` mentions no variable at a level `>= depth` in a relevant
/// position (a value of an arm that is also valid before the arm's binders;
/// irrelevant closures are ignored: conversion skips them). Conservative:
/// heads it does not know (`absurd`, `transport`, axioms) and exhausted
/// `fuel` answer `false`.
pub fn closed_below(v: &V, depth: u32, fuel: &mut usize) -> bool {
    if *fuel == 0 {
        return false;
    }
    *fuel -= 1;
    let arg = |a: &Arg, fuel: &mut usize| match a {
        Arg::Rel(x) => closed_below(x, depth, fuel),
        Arg::Irr(_) => true,
    };
    match &**v {
        Value::Sort(_) | Value::IntTy(_) | Value::Lit { .. } => true,
        Value::Pi { dom, cod, .. } => closed_below(dom, depth, fuel) && closure_closed(cod, depth, fuel),
        Value::Lam { dom, body, .. } => closed_below(dom, depth, fuel) && closure_closed(body, depth, fuel),
        Value::Sigma { fst, snd, .. } => closed_below(fst, depth, fuel) && closure_closed(snd, depth, fuel),
        Value::Pair { fst, snd } => closed_below(fst, depth, fuel) && arg(snd, fuel),
        Value::Eq { ty, lhs, rhs } => closed_below(ty, depth, fuel) && closed_below(lhs, depth, fuel) && closed_below(rhs, depth, fuel),
        Value::Refl { ty, val } => closed_below(ty, depth, fuel) && closed_below(val, depth, fuel),
        Value::Ind { params, .. } => params.iter().all(|p| closed_below(p, depth, fuel)),
        Value::Ctor { params, args, .. } => params.iter().all(|p| closed_below(p, depth, fuel)) && args.iter().all(|a| arg(a, fuel)),
        Value::Neu(n) => {
            let head = match &n.head {
                Head::Var(l) => l.0 < depth,
                Head::Global { args, .. } => args.iter().all(|a| arg(a, fuel)),
                Head::Prim { args, .. } => args.iter().all(|x| closed_below(x, depth, fuel)),
                _ => false,
            };
            head && n.spine.iter().all(|e| match e {
                Elim::App(a) => arg(a, fuel),
                Elim::Fst | Elim::Snd => true,
                Elim::Match { params, motive, arms, .. } => params.iter().all(|p| closed_below(p, depth, fuel)) && closure_closed(motive, depth, fuel) && arms.iter().all(|c| closure_closed(c, depth, fuel)),
            })
        }
    }
}

/// A closure's captured relevant values are closed below `depth`.
fn closure_closed(c: &Closure, depth: u32, fuel: &mut usize) -> bool {
    c.env.0.iter().all(|e| match e {
        EnvEntry::Rel(x) => closed_below(x, depth, fuel),
        EnvEntry::Irr(_) => true,
    })
}

/// The size of a continuation: the relevant term nodes of the arms of the
/// matches in `elims` (`None` when no match eliminates the value: the call
/// is in tail position, or only projected). Capped at `cap`.
/// The globals applied in the arms of the matches of `elims` (distinct, in
/// order of occurrence): the calls a continuation pushed into a callee's
/// leaves would carry along.
pub fn cont_globals(elims: &[Elim]) -> Vec<sandblaster_kernel::term::GlobalId> {
    let mut out = Vec::new();
    for e in elims {
        if let Elim::Match { arms, .. } = e {
            for a in arms {
                // relevant positions only (a dependent match's path
                // equation names the scrutinee's call in its type)
                crate::elab::tm::any_node(&crate::roundtrip::strip(&a.body), &mut |n| {
                    if let sandblaster_kernel::term::Term::Global(g) = n
                        && !out.contains(g)
                    {
                        out.push(*g);
                    }
                    false
                });
            }
        }
    }
    out
}

pub fn cont_nodes(elims: &[Elim], cap: usize) -> Option<usize> {
    let mut any = false;
    let mut n = 0usize;
    for e in elims {
        if let Elim::Match { arms, .. } = e {
            any = true;
            for a in arms {
                n = n.saturating_add(super::relevant_size(&a.body, cap));
                if n >= cap {
                    return Some(cap);
                }
            }
        }
    }
    any.then_some(n)
}
