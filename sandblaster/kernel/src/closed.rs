//! Closed evaluation for known-answer examples (DESIGN.md §15.7).
//!
//! [`eval_closed`] type-checks a closed term, evaluates it in the fully
//! transparent mode (every definition unfolds, opaque ones included), then
//! completes the value: a stuck application of a global to all its
//! arguments is replaced by its body evaluated on them (forcing the
//! arguments first), a stuck primitive or transport is recomputed on its
//! forced operands, and the eliminators of the stuck head are applied to
//! the result (a `match` on a constructor selects its arm). Constructor
//! fields and pair components are completed recursively. This is the
//! strategy of the front end's reference evaluator (the driver's
//! `Unfolder`), in the TCB: every step is a definitional equation (β, ι, δ
//! of the global's body, primitive literal semantics, `transport` on
//! convertible endpoints), so `eval_closed(t) = n` implies `⟦t⟧ = ⟦n⟧`.
//! The result must be first-order data (constructors, literals, pairs,
//! `refl`); anything else, and an exhausted budget, is an error.

use std::rc::Rc;

use crate::api::{Env, KernelErrorKind as K};
use crate::check::{Checker, Cx, KR, REL, kerr};
use crate::eval::Ev;
use crate::term::{Lvl, Tm};
use crate::util::{FxMap, arg_entry, tick};
use crate::value::{Arg, Budget, Elim, Head, V, VEnv, Value};

pub(crate) fn eval_closed(env: &Env, t: &Tm, b: &mut Budget) -> KR<Tm> {
    let ty = Checker::new(env).infer(&Cx::default(), t, REL, b)?;
    let root = VEnv::default();
    let mut g = Ground { env, ev: Ev::transparent(env).memoized(&root), memo: FxMap::default(), keep: Vec::new() };
    let v = g.ev.eval(&root, Lvl(0), t, b)?;
    let v = g.deep(v, b)?;
    if !first_order(&v) {
        return Err(kerr(K::IllFormed, "eval_closed: the result is not first-order data (it contains a function or a type)"));
    }
    Ok(crate::quote::Quoter::typed(env, Vec::new()).quote_root(Lvl(0), &v, Some(&ty), false))
}

/// Constructors, literals, pairs and `refl` all the way down (relevant
/// positions; iterative, linear in the value DAG).
fn first_order(v: &V) -> bool {
    let mut seen = crate::util::FxSet::default();
    let mut stack = vec![v.clone()];
    while let Some(v) = stack.pop() {
        if !seen.insert(Rc::as_ptr(&v) as *const () as usize) {
            continue;
        }
        let rel = |a: &Arg| if let Arg::Rel(x) = a { Some(x.clone()) } else { None };
        match &*v {
            Value::Lit { .. } | Value::Refl { .. } => {}
            Value::Ctor { args, .. } => stack.extend(args.iter().filter_map(rel)),
            Value::Pair { fst, snd } => stack.extend(std::iter::once(fst.clone()).chain(rel(snd))),
            _ => return false,
        }
    }
    true
}

fn stuck(what: &str) -> crate::api::KernelError {
    kerr(K::IllFormed, format!("eval_closed: the evaluation is stuck ({what})"))
}

struct Ground<'e> {
    env: &'e Env,
    ev: Ev<'e>,
    /// Completed values by the address of the input (kept alive in `keep`),
    /// so a shared value DAG is completed once per node.
    memo: FxMap<usize, V>,
    keep: Vec<V>,
}

impl Ground<'_> {
    /// Replace a stuck head by its value and re-apply the spine, until the
    /// value is not neutral.
    fn force(&mut self, mut v: V, b: &mut Budget) -> KR<V> {
        let depth = Lvl(0);
        loop {
            tick(b)?;
            let Value::Neu(n) = &*v else { return Ok(v) };
            let mut hv = match &n.head {
                Head::Global { def, args } => {
                    let d = self.env.defs.get(def.0 as usize).ok_or_else(|| stuck("unknown global"))?;
                    if args.len() != d.arity as usize {
                        return Err(stuck("a partially applied global"));
                    }
                    let args = self.deep_args(args, b)?;
                    self.ev.unfold(d, &args, depth, b)?
                }
                Head::Prim { op, args, proofs } => {
                    let args = args.iter().map(|a| self.deep(a.clone(), b)).collect::<KR<Vec<V>>>()?;
                    let r = self.ev.prim(*op, args, proofs.clone(), depth, b)?;
                    if matches!(&*r, Value::Neu(_)) {
                        return Err(stuck("a primitive outside its domain"));
                    }
                    r
                }
                Head::Transport { lhs, rhs, val, .. } => {
                    let (l, r) = (self.deep(lhs.clone(), b)?, self.deep(rhs.clone(), b)?);
                    if !crate::conv::Conv::transparent(self.env).conv(depth, &l, &r, b)? {
                        return Err(stuck("a transport between different values"));
                    }
                    val.clone()
                }
                Head::Var(_) => return Err(stuck("a free variable")),
                Head::Absurd { .. } | Head::Axiom { .. } => return Err(stuck("`absurd` or an axiom")),
            };
            for e in &n.spine {
                hv = self.force(hv, b)?;
                hv = match e {
                    Elim::App(a) => self.ev.apply(&hv, a.clone(), depth, b)?,
                    Elim::Fst => self.ev.fst(&hv),
                    Elim::Snd => self.ev.snd(&hv, depth, b)?,
                    Elim::Match { arms, .. } => match &*hv {
                        Value::Ctor { ctor, args, .. } => {
                            let arm = arms.get(*ctor as usize).ok_or_else(|| stuck("a match without this arm"))?;
                            self.ev.inst_n(arm, args.iter().map(arg_entry).collect(), depth, b)?
                        }
                        _ => return Err(stuck("a match on a non-constructor")),
                    },
                };
            }
            v = hv;
        }
    }

    fn deep_args(&mut self, args: &[Arg], b: &mut Budget) -> KR<Vec<Arg>> {
        args.iter()
            .map(|a| match a {
                Arg::Rel(x) => Ok(Arg::Rel(self.deep(x.clone(), b)?)),
                Arg::Irr(c) => Ok(Arg::Irr(c.clone())),
            })
            .collect()
    }

    /// [`Ground::force`], then complete constructor fields and pair
    /// components (functions and types are left as they are).
    fn deep(&mut self, v: V, b: &mut Budget) -> KR<V> {
        let key = Rc::as_ptr(&v) as *const () as usize;
        if let Some(r) = self.memo.get(&key) {
            return Ok(r.clone());
        }
        tick(b)?;
        let f = self.force(v.clone(), b)?;
        let r = match &*f {
            Value::Ctor { ind, ctor, params, args } => {
                Rc::new(Value::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args: self.deep_args(args, b)? })
            }
            Value::Pair { fst, snd } => {
                let fst = self.deep(fst.clone(), b)?;
                Rc::new(Value::Pair { fst, snd: self.deep_args(std::slice::from_ref(snd), b)?.remove(0) })
            }
            _ => f.clone(),
        };
        self.memo.insert(key, r.clone());
        self.keep.push(v);
        Ok(r)
    }
}
